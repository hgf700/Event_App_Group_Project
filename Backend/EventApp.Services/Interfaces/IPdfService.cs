using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface IPdfService
{
    Task GeneratePdfAsync();
}
