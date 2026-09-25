using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface IOauthRefreshService
{
    Task<string> EnsureValidAccessTokenAsync(string userId);
}
