namespace Backend.ExtraTools;

public class NullEmailSender
{
    public Task SendEmailAsync(string email, string subject, string htmlMessage)
    {
        // Pusty implementacja, która nic nie robi
        return Task.CompletedTask;
    }
}
