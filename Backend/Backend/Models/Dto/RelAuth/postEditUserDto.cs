using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto.RelAuth;

public class postEditUserDto
{
    [MaxLength(100)]
    public string newEmail { get; set; }
    
    [MaxLength(100)]
    public string currentPassword { get; set; }

    [MaxLength(100)]
    public string newPassword { get; set; }
}
