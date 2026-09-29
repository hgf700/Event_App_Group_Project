using EventApp.Services.Dto.RelAuth;
using EventApp.Services.Services.model;
using EventApp.Services.Services.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;

namespace EventApp.Services.Services.Interface;

public interface IAuthService
{
    Task<NormalRegisterResult> RegisterNormalAsync(postCreateUserNormDto dto);
    Task<NormalLoginResult> LoginNormalAsync(postLoginUserNormDto dto);
    Task<GoogleLoginResult> LoginGoogleOauth(ClaimsPrincipal principal);
}
