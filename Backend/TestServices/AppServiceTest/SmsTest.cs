using EventApp.Services.Services;
using NUnit.Framework;
using System;

namespace TestServices.AppServiceTest;

[TestFixture]
public class SmsTest
{
    private SmsService _service = null!;

    private string? _sendState;
    private string? _sid;
    private string? _token;
    private string? _smsReceiver;
    private string? _number;

    [SetUp]
    public void SetUp()
    {
        _service = new SmsService();

        // Zapamiętujemy oryginalne ENV
        _sendState = Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE");
        _sid = Environment.GetEnvironmentVariable("TWILIO_SID");
        _token = Environment.GetEnvironmentVariable("TWILIO_TOKEN");
        _smsReceiver = Environment.GetEnvironmentVariable("SMS_RECEIVER");
        _number = Environment.GetEnvironmentVariable("TWILIO_NUMBER");
    }

    [TearDown]
    public void TearDown()
    {
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", _sendState);
        Environment.SetEnvironmentVariable("TWILIO_SID", _sid);
        Environment.SetEnvironmentVariable("TWILIO_TOKEN", _token);
        Environment.SetEnvironmentVariable("SMS_RECEIVER", _smsReceiver);
        Environment.SetEnvironmentVariable("TWILIO_NUMBER", _number);
    }

    private static void ClearAllTwilioEnv()
    {
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", null);
        Environment.SetEnvironmentVariable("TWILIO_SID", null);
        Environment.SetEnvironmentVariable("TWILIO_TOKEN", null);
        Environment.SetEnvironmentVariable("SMS_RECEIVER", null);
        Environment.SetEnvironmentVariable("TWILIO_NUMBER", null);
    }

    private static void SetSendEnabled()
    {
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "true");
    }

    // ============================================================
    // 1. Feature flag wyłączony – nic nie robi
    // ============================================================

    [Test]
    public void SendSMS_WhenSendStateIsFalse_DoesNotThrow()
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");

        Assert.DoesNotThrow(() => _service.SendSMS("https://example.com/event/1"));
    }

    [Test]
    public void SendSMS_WhenSendStateIsMissing_DoesNotThrow()
    {
        ClearAllTwilioEnv();
        // TWILIO_SMS_SEND_STATE = null → bool.TryParse → false

        Assert.DoesNotThrow(() => _service.SendSMS("https://example.com/event/1"));
    }

    [Test]
    public void SendSMS_WhenSendStateIsGarbage_DoesNotThrow()
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "not-a-bool");

        // TryParse("not-a-bool") → false
        Assert.DoesNotThrow(() => _service.SendSMS("https://example.com/event/1"));
    }

    [TestCase("False")]
    [TestCase("FALSE")]
    [TestCase("0")]
    public void SendSMS_WhenSendStateIsFalsy_DoesNotThrow(string state)
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", state);

        Assert.DoesNotThrow(() => _service.SendSMS("https://example.com"));
    }

    // ============================================================
    // 2. Feature flag włączony – brakujące ENV
    // ============================================================

    [Test]
    public void SendSMS_WhenEnabledAndSidMissing_ThrowsInvalidOperationException()
    {
        ClearAllTwilioEnv();
        SetSendEnabled();
        // SID brak
        Environment.SetEnvironmentVariable("TWILIO_TOKEN", "token");
        Environment.SetEnvironmentVariable("SMS_RECEIVER", "+48111111111");
        Environment.SetEnvironmentVariable("TWILIO_NUMBER", "+48222222222");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("TWILIO_SID is not set."));
    }

    [Test]
    public void SendSMS_WhenEnabledAndTokenMissing_ThrowsInvalidOperationException()
    {
        ClearAllTwilioEnv();
        SetSendEnabled();
        Environment.SetEnvironmentVariable("TWILIO_SID", "ACxxxx");
        // TOKEN brak
        Environment.SetEnvironmentVariable("SMS_RECEIVER", "+48111111111");
        Environment.SetEnvironmentVariable("TWILIO_NUMBER", "+48222222222");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("TWILIO_TOKEN is not set."));
    }

    [Test]
    public void SendSMS_WhenEnabledAndReceiverMissing_ThrowsInvalidOperationException()
    {
        ClearAllTwilioEnv();
        SetSendEnabled();
        Environment.SetEnvironmentVariable("TWILIO_SID", "ACxxxx");
        Environment.SetEnvironmentVariable("TWILIO_TOKEN", "token");
        // SMS_RECEIVER brak
        Environment.SetEnvironmentVariable("TWILIO_NUMBER", "+48222222222");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("SMS_RECEIVER is not set."));
    }

    [Test]
    public void SendSMS_WhenEnabledAndNumberMissing_ThrowsInvalidOperationException()
    {
        ClearAllTwilioEnv();
        SetSendEnabled();
        Environment.SetEnvironmentVariable("TWILIO_SID", "ACxxxx");
        Environment.SetEnvironmentVariable("TWILIO_TOKEN", "token");
        Environment.SetEnvironmentVariable("SMS_RECEIVER", "+48111111111");
        // TWILIO_NUMBER brak

        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("TWILIO_NUMBER is not set."));
    }

    // Kolejność wyjątków: SID → TOKEN → RECEIVER → NUMBER
    [Test]
    public void SendSMS_WhenEnabledAndAllEnvMissing_ThrowsForSidFirst()
    {
        ClearAllTwilioEnv();
        SetSendEnabled();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("TWILIO_SID is not set."));
    }

    // ============================================================
    // 3. Edge cases – url
    // ============================================================

    [Test]
    public void SendSMS_WhenDisabled_NullUrl_DoesNotThrow()
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");

        // url nie jest używany, gdy flag = false
        Assert.DoesNotThrow(() => _service.SendSMS(null!));
    }

    [Test]
    public void SendSMS_WhenDisabled_EmptyUrl_DoesNotThrow()
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", "false");

        Assert.DoesNotThrow(() => _service.SendSMS(""));
    }

    // ============================================================
    // 4. bool.TryParse – akceptuje "true" w różnych formach
    // ============================================================

    [TestCase("true")]
    [TestCase("True")]
    [TestCase("TRUE")]
    public void SendSMS_WhenSendStateIsTrueVariant_RequiresEnvVars(string state)
    {
        ClearAllTwilioEnv();
        Environment.SetEnvironmentVariable("TWILIO_SMS_SEND_STATE", state);

        // Bez SID → wyjątek (oznacza, że weszło w blok if)
        var ex = Assert.Throws<InvalidOperationException>(() =>
            _service.SendSMS("https://example.com"));

        Assert.That(ex!.Message, Is.EqualTo("TWILIO_SID is not set."));
    }
}