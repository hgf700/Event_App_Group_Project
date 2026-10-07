using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelEvent;

public class postBuyTicketResponseDto
{
    public string url {  get; set; }
    public int? paymentId { get; set; }
}
