
using System.Diagnostics;
using System.Net.WebSockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Viotto.Security;

if (args.Length == 0)
{
    await RunParentAsync();
    return;
}

if (args is ["node", var nodeName, var portText, var peerBaseUrl])
{
    int port = int.Parse(portText);
    await RunNodeAsync(nodeName, port, peerBaseUrl);
    return;
}

await Console.Error.WriteLineAsync("Invalid arguments");
await Console.Error.WriteLineAsync("Run with no arguments to start both nodes");

static async Task RunParentAsync()
{
    var exePath = Assembly.GetEntryAssembly()?.Location
        ?? throw new InvalidOperationException("Could not find current executable path");

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        exePath = exePath.Replace(".dll", ".exe");
    }
    else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        exePath = exePath.Replace(".dll", string.Empty);
    }

    StartNode(exePath, "A", 5001, "http://localhost:5002");
    StartNode(exePath, "B", 5002, "http://localhost:5001");
}

static void StartNode(string exePath, string nodeName, int port, string peerBaseUrl)
{
    var nodeArgs = $"node {nodeName} {port} {peerBaseUrl}";

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        Process.Start(
            new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c start \"Node {nodeName}\" \"{exePath}\" {nodeArgs}",
                UseShellExecute = false
            }
        );

        return;
    }

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        var command = $"\"{exePath}\" {nodeArgs}; echo; echo Press ENTER to close; read";

        string[] terminalCommands =
        [
            $"alacritty -e bash -lc '{command}'",
            $"x-terminal-emulator -e bash -lc '{command}'",
            $"gnome-terminal -- bash -lc '{command}'",
            $"konsole -e bash -lc '{command}'",
            $"kitty bash -lc '{command}'",
        ];

        foreach (var terminalCommand in terminalCommands)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "alacritty",
                    UseShellExecute = false
                };

                psi.ArgumentList.Add("--title");
                psi.ArgumentList.Add($"Node {nodeName}");
                psi.ArgumentList.Add("--hold");
                psi.ArgumentList.Add("-e");
                psi.ArgumentList.Add(exePath);

                psi.ArgumentList.Add("node");
                psi.ArgumentList.Add(nodeName);
                psi.ArgumentList.Add(port.ToString());
                psi.ArgumentList.Add(peerBaseUrl);

                Process.Start(psi);

                return;
            }
            catch (Exception)
            {
                // Try next emulator
            }
        }

        throw new InvalidOperationException("Could not find a supported terminal emulator. Try running the two nodes manually.");
    }

    throw new PlatformNotSupportedException("Auto-spawn is only implemented for Windows and Linux.");
}

static async Task RunNodeAsync(string nodeName, int port, string peerBaseUrl)
{
    var selfBaseUrl = $"http://localhost:{port}";
    var peerWebSocketUrl = $"{peerBaseUrl.Replace("http://", "ws://")}/websocket";

    var buidler = WebApplication.CreateBuilder();

    buidler.Logging.ClearProviders();
    buidler.WebHost.UseUrls(selfBaseUrl);

    buidler.Services.AddHttpClient();

    await using var app = buidler.Build();

    app.UseWebSockets();

    var rsaEncrypter = new RsaEncrypter();

    var p = rsaEncrypter.GenerateBigPrime(1024);
    var q = rsaEncrypter.GenerateBigPrime(1024);

    var (publicKey, privateKey) = rsaEncrypter.GenerateKeys(p, q);

    app.MapGet("/public-key", () =>
    {
        return Results.Ok(publicKey);
    });

    app.MapGet("/websocket", async context =>
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync();

        var buffer = new byte[4096];

        using var memoryStream = new MemoryStream();


        while (socket.State == WebSocketState.Open)
        {
            var result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

            if (result.MessageType == WebSocketMessageType.Close)
            {
                return;
            }

            if (result.MessageType != WebSocketMessageType.Text)
            {
                throw new InvalidOperationException("Only text WebSocket messages are supported");
            }

            await memoryStream.WriteAsync(buffer, 0, result.Count);

            if (result.EndOfMessage)
            {
                var bytes = memoryStream.ToArray();
                memoryStream.SetLength(0);

                var decryptedMessage = DecryptBytes(bytes, privateKey);

                Console.Write('\r');
                Console.WriteLine($"[CHAT]: {decryptedMessage}");
                Console.Write("> ");
            }
        }
    });

    var _ = Task.Run(async () => app.RunAsync()).Unwrap();

    using var webSocket = await ConnectToPeerWebSocketAsync(new Uri(peerWebSocketUrl));

    RsaKey peerPublicKey;
    while (true)
    {
        await using var scope = app.Services.CreateAsyncScope();

        var httpClientFactory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();

        var httpClient = httpClientFactory.CreateClient();

        try
        {
            var response = await httpClient.GetAsync($"{peerBaseUrl}/public-key");

            response.EnsureSuccessStatusCode();

            var key = await response.Content.ReadFromJsonAsync<RsaKey>();

            if (key is null)
            {
                continue;
            }

            peerPublicKey = key;

            break;
        }
        catch (Exception)
        {
            await Task.Delay(100);
        }
    }

    while (true)
    {
        Console.Write("> ");

        var message = Console.ReadLine();

        if (message is null)
        {
            continue;
        }

        if (message == "/exit")
        {
            await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Exiting", CancellationToken.None);
            await app.StopAsync();
            return;
        }

        if (string.IsNullOrWhiteSpace(message))
        {
            continue;
        }

        var encryptedMessage = EncryptMessage(message, peerPublicKey);

        await webSocket.SendAsync(
            new ArraySegment<byte>(encryptedMessage),
            WebSocketMessageType.Text,
            endOfMessage: true,
            CancellationToken.None
        );
    }
}

static async Task<ClientWebSocket> ConnectToPeerWebSocketAsync(Uri peerWebSocketUrl)
{
    Exception? lastException = null;

    for (int i = 0; i < 100; i++)
    {
        try
        {
            var socket = new ClientWebSocket();
            await socket.ConnectAsync(peerWebSocketUrl, CancellationToken.None);
            return socket;
        }
        catch (Exception ex)
        {
            lastException = ex;
            await Task.Delay(100);
        }
    }

    throw new InvalidOperationException($"Could not connect to peer WebSocket {peerWebSocketUrl}", lastException);
}

static byte[] EncryptMessage(string message, RsaKey publicKey)
{
    var rsaEncrypter = new RsaEncrypter();
    var base64Encoder = new Base64Encoder();

    var messageBytes = Encoding.UTF8.GetBytes(message);

    var encryptedBytes = rsaEncrypter.Encrypt(messageBytes, publicKey);

    var encryptedBase64 = base64Encoder.ToBase64(encryptedBytes);

    var encryptedMessage = Encoding.UTF8.GetBytes(encryptedBase64);

    return encryptedMessage;
}

static string DecryptBytes(byte[] bytes, RsaKey privateKey)
{
    var rsaEncrypter = new RsaEncrypter();
    var base64Encoder = new Base64Encoder();

    var encryptedBas64 = Encoding.UTF8.GetString(bytes);

    var encryptedBytes = base64Encoder.FromBase64(encryptedBas64);

    var decryptedBytes = rsaEncrypter.Decrypt(encryptedBytes, privateKey);

    var decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

    return decryptedMessage;
}
