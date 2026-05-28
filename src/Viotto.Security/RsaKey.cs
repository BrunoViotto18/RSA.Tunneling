using System.Numerics;

namespace Viotto.Security;

public sealed record RsaKey
{
    public required BigInteger Product { get; init; }
    public required BigInteger Exponent { get; init; }
}
