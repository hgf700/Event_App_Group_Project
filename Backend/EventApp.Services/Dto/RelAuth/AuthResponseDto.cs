namespace EventApp.Services.Dto.RelAuth;

public class authResponseDto
{
    public string jwt { get; set; } = "";
    public string email { get; set; } = "";
    public string userRole { get; set; } = "";
}
