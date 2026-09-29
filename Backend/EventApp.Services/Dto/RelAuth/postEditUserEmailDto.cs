using System.ComponentModel.DataAnnotations;

namespace EventApp.Services.Dto.RelAuth;

public class postEditUserEmailDto
{
    [Required]
    [MinLength(1)]
    [MaxLength(100)]
    public string newEmail { get; set; }
}
