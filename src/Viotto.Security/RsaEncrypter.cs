using System.Diagnostics;
using System.Numerics;

namespace Viotto.Security;

public class RsaEncrypter
{
    public (RsaKey publicKey, RsaKey privateKey) GenerateKeys(BigInteger p, BigInteger q)
    {
        var n = p * q;

        var phi = (p - 1) * (q - 1);

        var e = GetPublicExponent(phi);

        var d = ModInverse(e, phi);

        var publicKey = new RsaKey
        {
            Product = n,
            Exponent = e
        };

        var privateKey = new RsaKey
        {
            Product = n,
            Exponent = d
        };

        return (publicKey, privateKey);
    }

    public byte[] Encrypt(Span<byte> data, RsaKey publicKey)
    {
        int plainBlockSize;
        int cipherBlockSize;
        checked
        {
            plainBlockSize = (int)((publicKey.Product.GetBitLength() - 1) / 8);
            cipherBlockSize = (int)((publicKey.Product.GetBitLength() + 7) / 8);
        }

        using var output = new MemoryStream();

        for (var offset = 0; offset < data.Length; offset += plainBlockSize)
        {
            var count = Math.Min(plainBlockSize, data.Length - offset);

            var block = data.Slice(offset, count);

            var number = new BigInteger(block, isUnsigned: true, isBigEndian: true);
            var cipheredNumber = BigInteger.ModPow(number, publicKey.Exponent, publicKey.Product);

            var cipherBlock = cipheredNumber.ToByteArray(isUnsigned: true, isBigEndian: true);

            var padding = new byte[cipherBlockSize - cipherBlock.Length];

            output.Write(padding);
            output.Write(cipherBlock);
        }

        return output.ToArray();
    }

    public byte[] Decrypt(Span<byte> data, RsaKey privateKey)
    {
        var cipherBlockSize = checked((int)((privateKey.Product.GetBitLength() + 7) / 8));

        using var output = new MemoryStream();

        for (var offset = 0; offset < data.Length; offset += cipherBlockSize)
        {
            var block = data.Slice(offset, cipherBlockSize);

            var cipheredNumber = new BigInteger(block, isUnsigned: true, isBigEndian: true);
            var number = BigInteger.ModPow(cipheredNumber, privateKey.Exponent, privateKey.Product);

            var cipherBlock = number.ToByteArray(isUnsigned: true, isBigEndian: true);

            output.Write(cipherBlock);
        }

        return output.ToArray();
    }

    private static BigInteger GetPublicExponent(BigInteger phi)
    {
        var e = 65537;

        if (e < phi && BigInteger.GreatestCommonDivisor(e, phi) == 1)
        {
            return e;
        }

        for (e = 3; e < phi; e += 2)
        {
            if (BigInteger.GreatestCommonDivisor(e, phi) == 1)
            {
                return e;
            }
        }

        throw new UnreachableException("Failed to find a valid value for phi while generating the key");
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        var m0 = m;
        BigInteger x0 = 0;
        BigInteger x1 = 1;

        while (a > 1)
        {
            var q = a / m;

            (a, m) = (m, a % m);
            (x0, x1) = (x1 - q * x0, x0);
        }

        if (x1 < 0)
        {
            x1 += m0;
        }

        return x1;
    }
}
