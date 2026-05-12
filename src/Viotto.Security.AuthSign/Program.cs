
using System.Text;
using Viotto.Security;

if (args.Length < 2 || args[0] is not "sign" and not "auth")
{
    throw new ArgumentException("Argumentos desconhecidos ou inálidos");
}

var sha256Hasher = new Sha256Hasher();
var base64Encoder = new Base64Encoder();

var filePath = args[1];

var fileContent = await File.ReadAllTextAsync(filePath);

var bytes = Encoding.UTF8.GetBytes(fileContent);

var hashedBytes = sha256Hasher.Hash(bytes);

var hash = base64Encoder.ToBase64(hashedBytes);

if (args[0] is "sign")
{
    Console.WriteLine($"Assinatura SHA256/base64 do arquivo: {hash}");
}
else if (args[0] is "auth")
{
    Console.Write("Digite a assinatura do arquivo [SHA256/base64]: ");
    var signature = Console.ReadLine();

    if (signature == hash)
    {
        Console.WriteLine("O arquivo é autêntico!");
    }
    else
    {
        Console.WriteLine("O arquivo não é autêntico, ou pode ter sido modificado!");
    }
}
