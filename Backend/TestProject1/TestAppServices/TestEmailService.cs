using EventApp.Services.Interfaces;
using EventApp.Services.Services;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestProject1.TestAppServices;

[TestFixture]
public class TestEmailService
{
    private EmailService _service = null!;

    [SetUp]
    public void SetUp()
    {
        _service = new EmailService();
    }

    [TestCase("user@example.com", null, 1, "user@example.com")]
    [TestCase(null!, "https://example.com", 1, "user@example.com")]
    [TestCase("user@example.com", null!, 1, "user@example.com")]
    [TestCase("user@example.com", "https://example.com", 1, null!)]
    [TestCase()]
    public void SendEmail_NullUrl_ThrowsArgumentNullException(string toEmail, string url, int userEventId, string email)
    {
        Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _service.SendEmail(toEmail, url!, userEventId, email));
    }

}
