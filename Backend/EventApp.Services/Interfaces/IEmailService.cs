namespace EventApp.Services.Interfaces;

public interface IEmailService
{
    void SendEmail(string toEmail, string url);
}
