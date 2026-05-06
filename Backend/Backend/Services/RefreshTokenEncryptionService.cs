using Microsoft.AspNetCore.DataProtection;

namespace Backend.Services;

public class RefreshTokenEncryptionService
{
    private readonly IDataProtector _protector;

    public RefreshTokenEncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("OAuthTokenProtection");
    }
    public string Encrypt(string plainText) => _protector.Protect(plainText);
    public string Decrypt(string cipherText) => _protector.Unprotect(cipherText);
}