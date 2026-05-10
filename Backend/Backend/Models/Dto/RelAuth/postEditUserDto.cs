namespace Backend.Models.Dto.RelAuth;

public class postEditUserDto
{
    public string? newEmail { get; set; }

    public string? currentPassword { get; set; }

    public string? newPassword { get; set; }
}
