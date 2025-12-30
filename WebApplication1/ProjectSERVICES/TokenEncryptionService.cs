using Microsoft.AspNetCore.DataProtection;

namespace WebApplication1.ProjectSERVICES
{
    public class TokenEncryptionService
    {
        private readonly IDataProtector _protector;

        public TokenEncryptionService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("OAuthTokenProtection");
        }
        public string Encrypt(string plainText) => _protector.Protect(plainText);
        public string Decrypt(string cipherText) => _protector.Unprotect(cipherText);
    }
}
