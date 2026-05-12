using System.Buffers.Binary;
using System.Numerics;

namespace Viotto.Security;

public sealed class Sha256Hasher
{
    private const int ChunkByteCount = 64;

    private static readonly uint[] InitialHash =
    [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ];

    private static readonly uint[] Constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    public byte[] Hash(ReadOnlySpan<byte> data)
    {
        Span<uint> chunk = stackalloc uint[ChunkByteCount];

        Span<uint> hashes = stackalloc uint[InitialHash.Length];
        InitialHash.CopyTo(hashes);

        var padding = (55 - data.Length) & 63;
        var loops = data.Length + 1 + padding + 8;
        uint blob = 0;
        for (int i = 0; i < loops; i++)
        {
            blob <<= 8;
            if (i < data.Length)
            {
                blob |= data[i];
            }
            else if (i == data.Length)
            {
                blob |= 0x80;
            }
            else if (i >= data.Length + 1 + padding)
            {
                var lengthByteIndex = 7 - (i + 8 - loops);
                var shift = lengthByteIndex * 8;

                blob |= (uint)((data.Length * 8L) >> shift);
            }

            if (i % 4 == 3)
            {
                var index = i % ChunkByteCount / 4;
                chunk[index] = blob;
                blob = 0;
            }

            if (i % 64 != 63)
            {
                continue;
            }

            ExpandMessage(chunk);
            CompressMessage(chunk, hashes);
        }

        var output = new byte[32];
        for (int i = 0; i < hashes.Length; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan().Slice(i * 4, 4), hashes[i]);
        }

        return output;
    }

    private static void ExpandMessage(Span<uint> words)
    {
        for (int i = 0; i < 64 - 16; i++)
        {
            var word0 = words[i];
            var word1 = words[i + 1];
            var word9 = words[i + 9];
            var word14 = words[i + 14];

            var sigma0
                = BitOperations.RotateRight(word1, 7)
                ^ BitOperations.RotateRight(word1, 18)
                ^ (word1 >> 3);

            var sigma1
                = BitOperations.RotateRight(word14, 17)
                ^ BitOperations.RotateRight(word14, 19)
                ^ (word14 >> 10);

            words[i + 16] = word0 + sigma0 + word9 + sigma1;
        }
    }

    private static void CompressMessage(Span<uint> words, Span<uint> hashes)
    {
        var a = hashes[0];
        var b = hashes[1];
        var c = hashes[2];
        var d = hashes[3];
        var e = hashes[4];
        var f = hashes[5];
        var g = hashes[6];
        var h = hashes[7];

        for (int i = 0; i < 64; i++)
        {
            var sigma0
                = BitOperations.RotateRight(a, 2)
                ^ BitOperations.RotateRight(a, 13)
                ^ BitOperations.RotateRight(a, 22);

            var sigma1
                = BitOperations.RotateRight(e, 6)
                ^ BitOperations.RotateRight(e, 11)
                ^ BitOperations.RotateRight(e, 25);

            var choice = (e & f) ^ (~e & g);
            var majority = (a & b) ^ (a & c) ^ (b & c);

            var temp1 = h + sigma1 + choice + Constants[i] + words[i];
            var temp2 = sigma0 + majority;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        unchecked
        {
            hashes[0] += a;
            hashes[1] += b;
            hashes[2] += c;
            hashes[3] += d;
            hashes[4] += e;
            hashes[5] += f;
            hashes[6] += g;
            hashes[7] += h;
        }
    }
}
