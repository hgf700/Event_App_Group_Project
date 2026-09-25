using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface IRefreshTokenEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string plainText);
}
