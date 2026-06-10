using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;

namespace Viotto.Security;

public class RsaEncrypter
{
    public BigInteger GenerateBigPrime(int bits, int rounds = 40)
    {
        if (bits < 2)
        {
            throw new ArgumentException("Bit size must be at least 2", nameof(bits));
        }

        if (rounds < 1)
        {
            throw new ArgumentException("Rounds must be at least 1", nameof(rounds));
        }

        while (true)
        {
            var candidate = GenerateRandomOddBigInteger(bits);

            if (IsProbablyPrime(candidate, rounds))
            {
                return candidate;
            }
        }
    }

    public (RsaKey publicKey, RsaKey privateKey) GenerateKeys(BigInteger p, BigInteger q)
    {
        if (p == q)
        {
            throw new ArgumentException("p and q must be different primes");
        }

        if (p < 3 || q < 3 || p % 2 == 0 || q % 2 == 0)
        {
            throw new ArgumentException("p and q must be odd primes greater than 2");
        }

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

        if (plainBlockSize < 1)
        {
            throw new ArgumentException("RSA key is too small");
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

    private static BigInteger GenerateRandomOddBigInteger(int bits)
    {
        int byteCount = (bits + 7) / 8;
        var bytes = new byte[byteCount];

        RandomNumberGenerator.Fill(bytes);

        int extraBits = byteCount * 8 - bits;

        bytes[0] &= (byte)(0xFF >> extraBits);

        bytes[0] |= (byte)(1 << (7 - extraBits));

        bytes[^1] |= 1;

        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private static bool IsProbablyPrime(BigInteger n, int rounds)
    {
        if (n < 2)
        {
            return false;
        }

        if (n < 4)
        {
            return true;
        }

        if (n % 2 == 0)
        {
            return false;
        }

        BigInteger d = n - 1;
        int s = 0;

        while (d % 2 == 0)
        {
            d /= 2;
            s++;
        }

        var bytes = new byte[n.GetByteCount(isUnsigned: true)];

        for (int i = 0; i < rounds; i++)
        {
            BigInteger a;

            do
            {
                RandomNumberGenerator.Fill(bytes);
                a = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            } while (a < 2 || a >= n - 2);

            BigInteger x = BigInteger.ModPow(a, d, n);

            if (x == 1 || x == n - 1)
            {
                continue;
            }

            bool passed = false;

            for (int r = 1; r < s; r++)
            {
                x = BigInteger.ModPow(x, 2, n);

                if (x == n - 1)
                {
                    passed = true;
                    break;
                }
            }

            if (!passed)
            {
                return false;
            }
        }

        return true;
    }

    private static BigInteger GetPublicExponent(BigInteger phi)
    {
        BigInteger e = 65537;

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
