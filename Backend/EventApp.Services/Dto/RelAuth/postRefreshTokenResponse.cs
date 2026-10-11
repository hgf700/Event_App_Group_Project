using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelAuth;

public class postRefreshTokenResponse
{
    public string accessToken { get; set; } = string.Empty;
}
