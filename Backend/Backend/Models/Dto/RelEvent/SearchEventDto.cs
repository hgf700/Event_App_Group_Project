using System.ComponentModel.DataAnnotations;

namespace Backend.Models.Dto.RelEvent;

public class SearchEventDto
{
    [MaxLength(100)]
    public string City { get; set; }
}
