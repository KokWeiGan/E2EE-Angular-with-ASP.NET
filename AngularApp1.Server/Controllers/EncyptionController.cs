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


        [HttpGet("getkey")]
        public IActionResult GetSecretKey()
        {
            try
            {
                return Ok(new { PublicKey = AsyncmetricEncyption.GetPublicKey(_rsa) });
            }
            catch (Exception ex)
            {
                // Log the exception (You can integrate a logging library here)
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }



        // Endpoint to get the public key
        [HttpGet("publickey")]
        public IActionResult GetPublicKey()
        {
            try
            {
                return Ok(new { PublicKey = AsyncmetricEncyption.GetPublicKey(_rsa) });
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
                return Ok(new { DecryptedData = AsyncmetricEncyption.DecryptData(_rsa, encryptedDataModel.Data) });
            }
            catch (Exception ex)
            {
                // Log the exception (You can integrate a logging library here)
                Console.WriteLine($"Error: {ex.Message}");
                return StatusCode(500, ex.Message);
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
