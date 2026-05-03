using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class Sha256Tests
{
    private readonly Base64Encoder _base64Encoder;
    private readonly Sha256Hasher _sut;

    public Sha256Tests()
    {
        _base64Encoder = new Base64Encoder();
        _sut = new Sha256Hasher();
    }

    [Theory]
    [InlineData("", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")]
    [InlineData("a", "ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=")]
    [InlineData("test", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "n0OQ+NMMLdkuyfCVtl4rmumwqSWlJY4kHJ8ekQ9zQxg=")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "s1Q5pKxvCUi21vnjxq8PX1kM4g8b3nCQ73lwaG7Gc4o=")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "MeulHDE6XAgiat8Y1KNZz9/Y0ugWsT9K+VL36mWE3Ps=")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Lz0zVDLHC1gK8Ojhs2dKfAINaDql9zqq7f3FWvkEwhw=")]
    public void Hash_ShouldHashTheInputData(string data, string expected)
    {
        // Arrange
        var bytes = Encoding.UTF8.GetBytes(data);

        // Act
        var output = _sut.Hash(bytes);

        // Assert
        var base64 = _base64Encoder.ToBase64(output);
        base64.Should().Be(expected);
    }
}
