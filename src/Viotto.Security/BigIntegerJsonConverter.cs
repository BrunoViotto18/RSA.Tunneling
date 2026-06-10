using System.Globalization;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Viotto.Security;

public sealed class BigIntegerJsonConverter : JsonConverter<BigInteger>
{
    public override BigInteger Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException(
                $"Expected a JSON string, but got {reader.TokenType}.");
        }

        string? value = reader.GetString();

        if (!BigInteger.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out BigInteger result))
        {
            throw new JsonException($"Invalid BigInteger value: {value}");
        }

        return result;
    }

    public override void Write(
        Utf8JsonWriter writer,
        BigInteger value,
        JsonSerializerOptions options)
    {
        writer.WriteStringValue(
            value.ToString(CultureInfo.InvariantCulture));
    }
}
