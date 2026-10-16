using EventApp.Services.Services;
using NUnit.Framework;
using System;
using System.Net;

namespace TestServices.AppServiceTest;

[TestFixture]
public class PdfHtmlTests
{

    public byte[] MinimalPng = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };

    // ============================================================
    // Happy path
    // ============================================================

    [Test]
    public void GenerateHtml_WithValidData_ContainsAllFields()
    {
        var html = PdfService.GenerateHtml(
            eventName: "Koncert Rock",
            eventDate: "2026-10-20 20:00",
            eventAddress: "Warszawa, Stadion",
            eventType: "Music",
            eventUrl: "https://example.com/event/1",
            email: "user@example.com",
            userEventId: 42,
            qrCode: MinimalPng);

        Assert.That(html, Does.Contain("Koncert Rock"));
        Assert.That(html, Does.Contain("2026-10-20 20:00"));
        Assert.That(html, Does.Contain("Warszawa, Stadion"));
        Assert.That(html, Does.Contain("Music"));
        Assert.That(html, Does.Contain("user@example.com"));
        Assert.That(html, Does.Contain("42"));
        Assert.That(html, Does.Contain("data:image/png;base64,"));
        Assert.That(html, Does.Contain("https://example.com/event/1"));
    }

    // ============================================================
    // XSS / HTML encoding
    // ============================================================

    [Test]
    public void GenerateHtml_EncodesHtmlInUserFacingFields()
    {
        var html = PdfService.GenerateHtml(
            eventName: "<script>alert(1)</script>",
            eventDate: "2026-01-01",
            eventAddress: "<b>Adres</b>",
            eventType: "Type&Co",
            eventUrl: "https://safe.example.com",
            email: "a@b.com",
            userEventId: 1,
            qrCode: MinimalPng);

        Assert.That(html, Does.Not.Contain("<script>"));
        Assert.That(html, Does.Contain(WebUtility.HtmlEncode("<script>alert(1)</script>")));
        Assert.That(html, Does.Contain(WebUtility.HtmlEncode("<b>Adres</b>")));
        Assert.That(html, Does.Contain(WebUtility.HtmlEncode("Type&Co")));
    }

    // ============================================================
    // URL safety
    // ============================================================

    [TestCase("https://example.com/event")]
    [TestCase("http://example.com/event")]
    public void GenerateHtml_AllowsHttpAndHttpsUrls(string url)
    {
        var html = PdfService.GenerateHtml(
            "Event", "date", "addr", "type", url, "e@e.com", 1, MinimalPng);

        Assert.That(html, Does.Contain($"href=\"{WebUtility.HtmlEncode(url)}\""));
    }

    [TestCase("javascript:alert(1)")]
    [TestCase("ftp://files.example.com")]
    [TestCase("not-a-url")]
    [TestCase("")]
    public void GenerateHtml_UnsafeOrInvalidUrl_FallsBackToHash(string url)
    {
        var html = PdfService.GenerateHtml(
            "Event", "date", "addr", "type", url, "e@e.com", 1, MinimalPng);

        Assert.That(html, Does.Contain("<a href=\"#\""));
    }

    // ============================================================
    // QR code
    // ============================================================

    [Test]
    public void GenerateHtml_EmbedsQrAsBase64()
    {
        var qr = new byte[] { 1, 2, 3, 4, 5 };
        var expectedBase64 = Convert.ToBase64String(qr);

        var html = PdfService.GenerateHtml(
            "E", "D", "A", "T", "https://x.com", "e@e.com", 1, qr);

        Assert.That(html, Does.Contain($"data:image/png;base64,{expectedBase64}"));
    }

    [Test]
    public void GenerateHtml_NullQrCode_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            PdfService.GenerateHtml(
                "E", "D", "A", "T", "https://x.com", "e@e.com", 1, null!));
    }

    // ============================================================
    // Null / empty z API (Ticketmaster) – BEZ walidacji „biznesowej”
    // ============================================================

    [Test]
    public void GenerateHtml_NullEventName_DoesNotThrow_AndEncodesEmpty()
    {
        // Obecny kod: WebUtility.HtmlEncode(null) → null
        // W interpolated string: {{eventName}} wstawi pusty string / null
        // Jeśli chcesz być odporny – w kodzie produkcyjnym zrób ?? ""

        Assert.DoesNotThrow(() =>
        {
            var html = PdfService.GenerateHtml(
                eventName: null!,
                eventDate: null!,
                eventAddress: null!,
                eventType: null!,
                eventUrl: "https://example.com",
                email: null!,
                userEventId: 99,
                qrCode: MinimalPng);

            Assert.That(html, Does.Contain("99")); // userEventId zawsze jest
            Assert.That(html, Does.Contain("data:image/png;base64,"));
        });
    }

    [Test]
    public void GenerateHtml_EmptyStrings_StillProducesValidLookingHtml()
    {
        var html = PdfService.GenerateHtml(
            "", "", "", "", "https://example.com", "", 7, MinimalPng);

        Assert.That(html, Does.Contain("<!DOCTYPE html>"));
        Assert.That(html, Does.Contain("7"));
        Assert.That(html, Does.Contain("Potwierdzenie zakupu biletu"));
    }
}