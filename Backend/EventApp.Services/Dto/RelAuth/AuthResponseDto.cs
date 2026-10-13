namespace EventApp.Services.Dto.RelAuth;

public class authResponseDto
{
    public string jwt { get; set; } = string.Empty;
    public string refreshToken { get; set; } = string.Empty;
    public string email { get; set; } = string.Empty;
    public string userRole { get; set; } = string.Empty;
}
