using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto.RelAuth;

public class postEditUserPassword
{
    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string oldPassword { get; set; }
    
    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string newPassword { get; set; }
}
