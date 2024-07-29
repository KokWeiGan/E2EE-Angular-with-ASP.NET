using System.Security.Cryptography;

public class KeyManager
{
    public RSA CurrentRsaKey { get; private set; }
    public DateTime KeyGeneratedAt { get; private set; }
    public TimeSpan KeyValidityPeriod { get; set; } = TimeSpan.FromDays(30); // Example validity period

    public KeyManager()
    {
        GenerateNewKey();
    }

    public void GenerateNewKey()
    {
        CurrentRsaKey = RSA.Create(2048); // Generate a new RSA key pair
        KeyGeneratedAt = DateTime.UtcNow;
    }

    public bool IsKeyExpired()
    {
        return DateTime.UtcNow - KeyGeneratedAt > KeyValidityPeriod;
    }
}
