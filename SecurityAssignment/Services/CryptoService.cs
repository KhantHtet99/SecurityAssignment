using Microsoft.AspNetCore.DataProtection;

namespace SecurityAssignment.Services
{
    public class CryptoService
    {
        private readonly IDataProtector _protector;

        public CryptoService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("SecurityAssignment.SensitiveField.v1");
        }

        public string Encrypt(string plain) => _protector.Protect(plain);
        public string Decrypt(string cipher) => _protector.Unprotect(cipher);
    }
}
