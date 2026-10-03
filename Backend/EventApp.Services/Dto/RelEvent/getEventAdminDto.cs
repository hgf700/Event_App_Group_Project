using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelEvent;

public class getEventAdminDto
{
    public int? id { get; set; }
    public string? nameOfEvent { get; set; }
    public DateTime? startOfEvent { get; set; }
    public string? city { get; set; }
    public string? nameOfClub { get; set; }
}
