using EventApp.Services.Interfaces;
using Microsoft.AspNetCore.DataProtection;

namespace EventApp.Services.Services;

public class RefreshTokenEncryptionService : IRefreshTokenEncryptionService
{
    private readonly IDataProtector _protector;

    public RefreshTokenEncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("OAuthTokenProtection");
    }
    public string Encrypt(string plainText) => _protector.Protect(plainText);
    public string Decrypt(string cipherText) => _protector.Unprotect(cipherText);
}