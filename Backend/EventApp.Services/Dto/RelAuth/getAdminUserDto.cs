using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelAuth;

public class getAdminUserDto
{
    public string id { get; set; }
    public string email {  get; set; }
    public string userName { get; set; }
    public IList<string> roles { get; set; } = new List<string>();
}
