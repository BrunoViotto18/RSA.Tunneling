using System;
using System.Numerics;
using System.Text;
using AwesomeAssertions;

namespace Viotto.Security.UnitTests;

public class RsaEncrypterTests
{
    private readonly RsaEncrypter _sut;

    public RsaEncrypterTests()
    {
        _sut = new RsaEncrypter();
    }

    [Theory]
    [InlineData(61, 53, 3233, 7, 1783)]
    public void GenerateKeys_ShouldGenerateRsaKeys(BigInteger p, BigInteger q, BigInteger product, BigInteger publicExponent, BigInteger privateExponent)
    {
        // Arrange
        var expectedPublicKey = new RsaKey
        {
            Product = product,
            Exponent = publicExponent
        };
        var expectedPrivateKey = new RsaKey
        {
            Product = product,
            Exponent = privateExponent
        };

        // Act
        var (publicKey, privateKey) = _sut.GenerateKeys(p, q);

        // Assert
        publicKey.Should().Be(expectedPublicKey);
        privateKey.Should().Be(expectedPrivateKey);
    }

    [Theory]
    [InlineData(61, 53, "test")]
    [InlineData(61, 53, "This is a test message")]
    public void Encrypter_ShouldEncryptAndDecryptMessages(BigInteger p, BigInteger q, string originalMessage)
    {
        // Arrange
        var (publicKey, privateKey) = _sut.GenerateKeys(p, q);
        var messageBytes = Encoding.UTF8.GetBytes(originalMessage);

        // Act
        var encrypted = _sut.Encrypt(messageBytes, publicKey);
        var decrypted = _sut.Decrypt(encrypted, privateKey);

        // Assert
        var decryptedMessage = Encoding.UTF8.GetString(decrypted);
        decryptedMessage.Should().Be(originalMessage);
    }
}
