using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        private static KeyManager _keyManager = new KeyManager();

        // Endpoint to get the public key
        [HttpGet("publickey")]
        public IActionResult GetPublicKey()
        {
            try
            {
                // Ensure the key is up-to-date
                if (_keyManager.IsKeyExpired())
                {
                    _keyManager.GenerateNewKey();
                }

                var publicKeyPem = GetPublicKeyPem(_keyManager.CurrentRsaKey);
                return Ok(new { PublicKey = publicKeyPem });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        // Endpoint to get both public and private keys (for debugging only)
        [HttpGet("debugkeys")]
        public IActionResult GetDebugKeys()
        {
            // Ensure that this endpoint is used only in development environments
            if (!IsDevelopmentEnvironment())
            {
                return Unauthorized("Access to debug keys is restricted.");
            }

            try
            {
                // Ensure the key is up-to-date
                if (_keyManager.IsKeyExpired())
                {
                    _keyManager.GenerateNewKey();
                }

                var publicKeyPem = GetPublicKeyPem(_keyManager.CurrentRsaKey);
                var privateKeyPem = GetPrivateKeyPem(_keyManager.CurrentRsaKey);
                return Ok(new { PublicKey = publicKeyPem, PrivateKey = privateKeyPem });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        // Endpoint to decrypt the data
        [HttpPost("decrypt")]
        public IActionResult DecryptData([FromBody] EncryptedDataModel encryptedDataModel)
        {
            try
            {
                // Ensure the key is up-to-date
                if (_keyManager.IsKeyExpired())
                {
                    _keyManager.GenerateNewKey();
                }

                var decryptedData = AsyncmetricEncyption.DecryptData(_keyManager.CurrentRsaKey, encryptedDataModel.Data);
                return Ok(new { DecryptedData = decryptedData });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, ex.Message);
            }
        }

        private static string GetPublicKeyPem(RSA rsa)
        {
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            return ConvertToPem(publicKey, "PUBLIC KEY");
        }

        private static string GetPrivateKeyPem(RSA rsa)
        {
            var privateKey = rsa.ExportRSAPrivateKey();
            return ConvertToPem(privateKey, "PRIVATE KEY");
        }

        private static string ConvertToPem(byte[] keyBytes, string keyType)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {keyType}-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine($"-----END {keyType}-----");
            return sb.ToString();
        }

        private static bool IsDevelopmentEnvironment()
        {
            return Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";
        }
    }

    public class EncryptedDataModel
    {
        public string Data { get; set; }
    }
}
