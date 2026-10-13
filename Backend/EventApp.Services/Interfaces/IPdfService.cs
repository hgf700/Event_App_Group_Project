using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface IPdfService
{
    Task GeneratePdfAsync(
        string eventName,
        string eventDate,
        string eventAddress,
        string eventType,
        string eventUrl,
        string email,
        int userEventId,
        byte[] qrCode
        );
}
