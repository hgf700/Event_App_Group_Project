using System.ComponentModel.DataAnnotations;

namespace Backend.Dto.RelAuth;

public class postCreateUserNormDto
{
    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string email { get; set; }

    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string password { get; set; }

}
