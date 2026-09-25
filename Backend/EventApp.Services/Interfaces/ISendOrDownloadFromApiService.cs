using EventApp.Services.Dto.RelEvent;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Interfaces;

public interface ISendOrDownloadFromApiService
{
    Task<List<postSearchOrDownloadQueryDto>> FetchAndSaveEventsAsync(string? city = null);
}
