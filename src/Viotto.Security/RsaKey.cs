using System.Numerics;
using System.Text.Json.Serialization;

namespace Viotto.Security;

public sealed record RsaKey
{
    [JsonConverter(typeof(BigIntegerJsonConverter))]
    public required BigInteger Product { get; init; }

    [JsonConverter(typeof(BigIntegerJsonConverter))]
    public required BigInteger Exponent { get; init; }
}
