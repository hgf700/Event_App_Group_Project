using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface ISmsService
{
    void SendSMS(string url);
}
