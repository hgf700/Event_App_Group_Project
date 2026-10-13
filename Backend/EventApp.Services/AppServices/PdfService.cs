
using EventApp.Services.Interfaces;
using Microsoft.Playwright;
using System.Net;

namespace EventApp.Services.Services;

public class PdfService : IPdfService
{
    public string EventName { get; }
    public string EventDate { get; }
    public string EventAddress { get; }
    public string EventType { get; }
    public string EventUrl { get; }
    public string Email { get; }
    public int UserEventId { get; }
    private readonly byte[] _qrCode;

    public PdfService(
        string eventName,
        string eventDate,
        string eventAddress,
        string eventType,
        string eventUrl,
        string email,
        int userEventId,
        byte[] qrCode)
    {
        EventName = eventName;
        EventDate = eventDate;
        EventAddress = eventAddress;
        EventType = eventType;
        EventUrl = eventUrl;
        Email = email;
        UserEventId = userEventId;
        _qrCode = qrCode;
    }

    public async Task GeneratePdfAsync()
    {
        var generatedPath= Path.Combine(Directory.GetCurrentDirectory(), "Generated");
        Directory.CreateDirectory(generatedPath);

        var pdfPath = Path.Combine(generatedPath, $"ticket-{UserEventId}-{Email}.pdf");

        var html = GenerateHtml();

        using var playwright = await Playwright.CreateAsync();

        await using var browser = await playwright.Chromium.LaunchAsync(
            new BrowserTypeLaunchOptions
            {
                Headless = true
            });

        var page = await browser.NewPageAsync();

        await page.SetContentAsync(html);

        await page.PdfAsync(new PagePdfOptions
        {
            Path = pdfPath,
            Format = "A4",
            PrintBackground = true,
            PreferCSSPageSize = true
        });
    }

    private string GenerateHtml()
    {
        // Kod QR wstawiamy bezpośrednio jako obraz Base64.
        var qrBase64 = Convert.ToBase64String(_qrCode);

        // Kodujemy dane tekstowe, aby nie traktować ich jako HTML.
        var eventName = WebUtility.HtmlEncode(EventName);
        var eventDate = WebUtility.HtmlEncode(EventDate);
        var eventAddress = WebUtility.HtmlEncode(EventAddress);
        var eventType = WebUtility.HtmlEncode(EventType);
        var email = WebUtility.HtmlEncode(Email);
        var eventUrl = WebUtility.HtmlEncode(EventUrl);

        return $$"""
        <!DOCTYPE html>
        <html lang="pl">
        <head>
            <meta charset="UTF-8">

            <style>
                @page {
                    size: A4;
                    margin: 15mm;
                }

                * {
                    box-sizing: border-box;
                }

                body {
                    margin: 0;
                    font-family: Arial, Helvetica, sans-serif;
                    color: #243047;
                    background: #ffffff;
                    font-size: 14px;
                }

                .ticket {
                    border: 1px solid #dce3ed;
                    border-radius: 12px;
                    overflow: hidden;
                }

                .header {
                    background: #1f4e79;
                    color: white;
                    padding: 28px 30px;
                }

                .header h1 {
                    margin: 0 0 8px;
                    font-size: 25px;
                }

                .header p {
                    margin: 0;
                    color: #e1ebf7;
                    font-size: 13px;
                }

                .content {
                    padding: 30px;
                }

                .section-title {
                    color: #1f4e79;
                    font-size: 17px;
                    margin: 0 0 22px;
                }

                .event-name {
                    font-size: 22px;
                    font-weight: bold;
                    margin-bottom: 25px;
                    overflow-wrap: anywhere;
                }

                .details {
                    width: 100%;
                    border-collapse: collapse;
                }

                .details td {
                    padding: 13px 10px;
                    border-bottom: 1px solid #e7ebf0;
                    vertical-align: top;
                    overflow-wrap: anywhere;
                }

                .details td:first-child {
                    width: 36%;
                    color: #667085;
                }

                .details td:last-child {
                    font-weight: bold;
                }

                .buyer {
                    margin-top: 25px;
                    padding: 18px;
                    background: #f4f7fb;
                    border-radius: 8px;
                    overflow-wrap: anywhere;
                }

                .buyer p {
                    margin: 6px 0;
                }

                .qr-section {
                    margin-top: 35px;
                    text-align: center;
                    page-break-inside: avoid;
                }

                .qr-section h2 {
                    font-size: 17px;
                    margin-bottom: 10px;
                }

                .qr-code {
                    width: 190px;
                    height: 190px;
                    object-fit: contain;
                }

                .qr-description {
                    color: #667085;
                    font-size: 12px;
                    margin-top: 8px;
                }

                .event-link {
                    margin-top: 22px;
                    text-align: center;
                    overflow-wrap: anywhere;
                }

                .event-link a {
                    color: #1f4e79;
                    text-decoration: none;
                }

                .footer {
                    border-top: 1px solid #e7ebf0;
                    padding: 18px 30px;
                    text-align: center;
                    color: #667085;
                    font-size: 11px;
                }
            </style>
        </head>

        <body>
            <div class="ticket">

                <header class="header">
                    <h1>Potwierdzenie zakupu biletu</h1>
                    <p>Twój bilet na wydarzenie</p>
                </header>

                <main class="content">

                    <h2 class="section-title">
                        Informacje o wydarzeniu
                    </h2>

                    <div class="event-name">
                        {{eventName}}
                    </div>

                    <table class="details">
                        <tr>
                            <td>Data wydarzenia</td>
                            <td>{{eventDate}}</td>
                        </tr>

                        <tr>
                            <td>Adres</td>
                            <td>{{eventAddress}}</td>
                        </tr>

                        <tr>
                            <td>Typ wydarzenia</td>
                            <td>{{eventType}}</td>
                        </tr>

                        <tr>
                            <td>Numer rezerwacji</td>
                            <td>{{UserEventId}}</td>
                        </tr>
                    </table>

                    <div class="buyer">
                        <p><strong>Dane kupującego</strong></p>
                        <p>E-mail: {{email}}</p>
                        <p>Numer biletu: {{UserEventId}}</p>
                    </div>

                    <section class="qr-section">
                        <h2>Twój kod QR</h2>

                        <img
                            class="qr-code"
                            src="data:image/png;base64,{{qrBase64}}"
                            alt="Kod QR biletu" />

                        <p class="qr-description">
                            Pokaż kod QR podczas wejścia na wydarzenie.
                        </p>
                    </section>

                    <div class="event-link">
                        <a href="{{eventUrl}}">
                            Zobacz stronę wydarzenia
                        </a>
                    </div>

                </main>

                <footer class="footer">
                    Potwierdzenie zakupu · {{eventName}}
                </footer>

            </div>
        </body>
        </html>
        """;
    }
}
