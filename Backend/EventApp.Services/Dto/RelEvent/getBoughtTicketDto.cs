using EventApp.Services.Model;
using System;
using System.Collections.Generic;
using System.Text;

namespace EventApp.Services.Dto.RelEvent;

public class getBoughtTicketDto
{
    public string? userId { get; set; }
    public string? userEmail{ get; set; }
    
    public int? eventId { get; set; }
    public string? eventName { get; set; }
    public DateTime? eventDate { get; set; }

    public DateTime createdAt { get; set; }
    public DateTime? paymentStateAt { get; set; }
    public StatesOfTicket paymentState { get; set; }

    public DateTime? ticketStateAt { get; set; }
    public TicketState ticketState { get; set; }

    public string? paymentId { get; set; }
}