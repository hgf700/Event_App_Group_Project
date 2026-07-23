using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto.RelEvent;

public class postSearchEventDto
{
    [MaxLength(100)]
    public string? city { get; set; }
}
