using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelBookmark;

public class getBookmakrDto
{
    public string? userId { get; set; }
    public int? eventId { get; set; }
    public string? eventName { get; set; }
}
