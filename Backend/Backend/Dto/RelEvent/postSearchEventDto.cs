using System.ComponentModel.DataAnnotations;

namespace Backend.Dto.RelEvent;

public class postSearchEventDto
{
    [MaxLength(100)]
    public string? city { get; set; }
}
