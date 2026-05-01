namespace Backend.Models.Dto;

public class postRegisterUserDto
{
    public string Email { get; set; }
    public string Password { get; set; }
    public string ConfirmPassword { get; set; }
    public bool IsOAuth { get; set; } = false;
    public string? GoogleId { get; set; }
}
