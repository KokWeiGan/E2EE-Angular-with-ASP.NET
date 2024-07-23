using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptionController : ControllerBase
    {
        private static readonly RSA _rsa = RSA.Create(2048); // Initialize RSA once

        // Endpoint to get the public key
        [HttpGet("publickey")]
        public IActionResult GetPublicKey()
        {
            try
            {
                var publicKey = _rsa.ExportSubjectPublicKeyInfo(); // Export public key in binary format
                var publicKeyPem = ConvertToPem(publicKey, "PUBLIC KEY");
                return Ok(new { PublicKey = publicKeyPem });
            }
            catch (Exception ex)
            {
                // Log the exception (You can integrate a logging library here)
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
                var encryptedData = Convert.FromBase64String(encryptedDataModel.Data);

                // Ensure thread safety by creating a new RSA instance for decryption
                using (var rsa = RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(_rsa.ExportRSAPrivateKey(), out _);
                    var decryptedBytes = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                    var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                    return Ok(new { DecryptedData = decryptedText });
                }
            }
            catch (Exception ex)
            {
                // Log the exception (You can integrate a logging library here)
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        private static string ConvertToPem(byte[] keyBytes, string keyType)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {keyType}-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine($"-----END {keyType}-----");
            return sb.ToString();
        }
    }

    public class EncryptedDataModel
    {
        public string Data { get; set; }
    }
}
