using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto.RelAuth;

public class postEditUserEmail
{
    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string newEmail { get; set; }
}
