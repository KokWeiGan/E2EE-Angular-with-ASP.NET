using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Tests
{
    [TestClass]
    public class EncryptionServiceTests
    {
        private EncryptionService _encryptionService;
        private static readonly RSA _rsa = RSA.Create(2048); // Initialize RSA once

        [TestInitialize]
        public void Setup()
        {
            string base64Key, base64Iv;
            KeyGenerator.GenerateKeyAndIv(out base64Key, out base64Iv);
            _encryptionService = new EncryptionService(base64Key, base64Iv);
        }

        [TestMethod]
        public void GetPublicKey_ShouldReturnPublicKey()
        {
            // Act
            var publicKey = AsyncmetricEncyption.GetPublicKey(_rsa);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(publicKey));
            Assert.IsTrue(publicKey.Contains("-----BEGIN PUBLIC KEY-----"));
            Assert.IsTrue(publicKey.Contains("-----END PUBLIC KEY-----"));
        }

        [TestMethod]
        public void DecryptData_ShouldReturnOriginalData()
        {
            // Arrange
            var plainText = "Hello, World!";
            byte[] encryptedData;
            using (RSA rsa = RSA.Create())
            {
                var publicKey = AsyncmetricEncyption.GetPublicKey(_rsa);
                rsa.ImportFromPem(publicKey.ToCharArray());
                encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
            }
            var base64EncryptedData = Convert.ToBase64String(encryptedData);

            // Act
            var decryptedData = AsyncmetricEncyption.DecryptData(_rsa, base64EncryptedData);

            // Assert
            Assert.AreEqual(plainText, decryptedData);
        }

        [TestMethod]
        public void DecryptData_WithInvalidData_ShouldThrowException()
        {
            // Arrange
            var invalidBase64Data = "InvalidBase64String";

            // Act & Assert
            Assert.ThrowsException<FormatException>(() => AsyncmetricEncyption.DecryptData(_rsa, invalidBase64Data));
        }

        [TestMethod]
        public void Encrypt_ShouldReturnEncryptedString()
        {
            // Arrange
            var plainText = "Hello, World!";

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(encryptedText));
            Assert.AreNotEqual(plainText, encryptedText);
        }

        [TestMethod]
        public void Decrypt_ShouldReturnDecryptedString()
        {
            // Arrange
            var plainText = "Hello, World!";
            var encryptedText = _encryptionService.Encrypt(plainText);

            // Act
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void EncryptDecrypt_ShouldReturnOriginalString()
        {
            // Arrange
            var plainText = "Hello, World!";

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void Encrypt_EmptyString_ShouldReturnNonEmptyString()
        {
            // Arrange
            var plainText = string.Empty;

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(encryptedText));
        }

        [TestMethod]
        public void Decrypt_EmptyString_ShouldReturnEmptyString()
        {
            // Arrange
            var plainText = string.Empty;
            var encryptedText = _encryptionService.Encrypt(plainText);

            // Act
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void EncryptDecrypt_SpecialCharacters_ShouldReturnOriginalString()
        {
            // Arrange
            var plainText = "!@#$%^&*()_+-=<>?";

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void Decrypt_NullString_ShouldThrowArgumentNullException()
        {
            // Arrange
            string cipherText = null;

            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => _encryptionService.Decrypt(cipherText));
        }

        [TestMethod]
        public void EncryptDecrypt_LargeData_ShouldReturnOriginalString()
        {
            // Arrange
            var plainText = new string('A', 10000); // Large string of 10,000 characters

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void EncryptDecrypt_DifferentDataTypes_ShouldHandleProperly()
        {
            // Arrange
            var plainTextInt = 12345.ToString();
            var plainTextBool = true.ToString();

            // Act
            var encryptedTextInt = _encryptionService.Encrypt(plainTextInt);
            var decryptedTextInt = _encryptionService.Decrypt(encryptedTextInt);
            var encryptedTextBool = _encryptionService.Encrypt(plainTextBool);
            var decryptedTextBool = _encryptionService.Decrypt(encryptedTextBool);

            // Assert
            Assert.AreEqual(plainTextInt, decryptedTextInt);
            Assert.AreEqual(plainTextBool, decryptedTextBool);
        }

        [TestMethod]
        public void Decrypt_InvalidBase64String_ShouldThrowFormatException()
        {
            // Arrange
            var invalidBase64Data = "InvalidBase64String";

            // Act & Assert
            Assert.ThrowsException<FormatException>(() => AsyncmetricEncyption.DecryptData(_rsa, invalidBase64Data));
        }

        [TestMethod]
        public void GetPublicKey_ShouldReturnValidFormat()
        {
            // Act
            var publicKey = AsyncmetricEncyption.GetPublicKey(_rsa);

            // Assert
            Assert.IsTrue(publicKey.StartsWith("-----BEGIN PUBLIC KEY-----"));
            Assert.IsTrue(publicKey.EndsWith("-----END PUBLIC KEY-----"));
            Assert.IsTrue(publicKey.Length > 50); // Ensure it has some content
        }

        [TestMethod]
        public void EncryptDecrypt_Whitespace_ShouldReturnOriginalString()
        {
            // Arrange
            var plainText = "    "; // String with whitespace

            // Act
            var encryptedText = _encryptionService.Encrypt(plainText);
            var decryptedText = _encryptionService.Decrypt(encryptedText);

            // Assert
            Assert.AreEqual(plainText, decryptedText);
        }

        [TestMethod]
        public void EncryptData_ShouldHandleLargeData()
        {
            // Arrange
            var largeData = new string('B', 50000); // Large data string of 50,000 characters

            // Act
            var encryptedData = _encryptionService.Encrypt(largeData);

            // Assert
            Assert.IsFalse(string.IsNullOrEmpty(encryptedData));
        }
    }
}
