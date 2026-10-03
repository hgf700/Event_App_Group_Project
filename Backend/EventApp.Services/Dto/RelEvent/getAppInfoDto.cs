using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelEvent;

public class getAppInfoDto
{
    public int activeUserCount { get; set; }
    public int boughtTickets { get; set; }
    public int activeTickets { get; set; }
}
