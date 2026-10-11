namespace EventApp.Services.Interfaces;

public interface IEmailService
{
    Task SendEmail(string toEmail, string url, int userEventId, string email);
}
