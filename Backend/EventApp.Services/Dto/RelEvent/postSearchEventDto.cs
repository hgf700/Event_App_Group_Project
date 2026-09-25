using System.ComponentModel.DataAnnotations;

namespace EventApp.Services.Dto.RelEvent;

public class postSearchEventDto
{
    [MaxLength(100)]
    public string? city { get; set; }
}
