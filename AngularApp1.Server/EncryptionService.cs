using System.Security.Cryptography;
using System.Text;
public static class KeyGenerator
{
    public static void GenerateKeyAndIv(out string base64Key, out string base64Iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            aes.GenerateIV();
            base64Key = Convert.ToBase64String(aes.Key);
            base64Iv = Convert.ToBase64String(aes.IV);
        }
    }
}
public class EncryptionService
{
    private readonly byte[] key;
    private readonly byte[] iv;

    public EncryptionService(string key, string iv)
    {
        this.key = Convert.FromBase64String(key);
        this.iv = Convert.FromBase64String(iv);
    }

    public string Encrypt(string plainText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }
    }

    public string Decrypt(string cipherText)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }



}

public class AsyncmetricEncyption
{
    public static string GetPublicKey(RSA rsa)
    {
        var publicKey = rsa.ExportSubjectPublicKeyInfo(); // Export public key in binary format
        var publicKeyPem = ConvertToPem(publicKey, "PUBLIC KEY");
        return publicKeyPem;
    }

    public static string DecryptData(RSA rsa, string base64EncryptedData)
    {
        var encryptedData = Convert.FromBase64String(base64EncryptedData);
        rsa.ImportRSAPrivateKey(rsa.ExportRSAPrivateKey(), out _);
        var decryptedBytes = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
        var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
        return decryptedText;
    }

    public static string ConvertToPem(byte[] keyBytes, string keyType)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {keyType}-----");
        sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine($"-----END {keyType}-----");
        return sb.ToString();
    }
}