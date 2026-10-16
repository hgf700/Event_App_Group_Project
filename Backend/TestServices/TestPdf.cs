using EventApp.Domain.Model;
using EventApp.Services.Services;
using Microsoft.AspNetCore.Identity;
using Moq;
using Stripe;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServices;

[TestFixture]
public class TestPdf
{
    private PdfService _service = null!;


    [SetUp]
    public void SetUp()
    {
        _service = new PdfService();
    }

    [TearDown]
    public void TearDown()
    {
    
    }

    [TestCase("a", "2", "1", "1", "1" ,"1", 1, new byte[] { 0x89, 0x50, 0x4E, 0x47 });]
    public void GeneratePdf(string eventName,
        string eventDate,
        string eventAddress,
        string eventType,
        string eventUrl,
        string email,
        int userEventId,
        byte[] qrCode)
    {
        //string generatedPath = Path.Combine(Directory.GetCurrentDirectory(), "Generated");
        //Directory.CreateDirectory(generatedPath);

        //string pdfPath = Path.Combine(generatedPath, $"ticket-{userEventId}-{email}.pdf");
        //string qrPath = Path.Combine(generatedPath, $"QR-{userEventId}-{email}.png");

        //// Upewniamy się, że PDF nie istnieje
        //if (File.Exists(pdfPath)) File.Delete(pdfPath);

        //// Tworzymy QR, żeby test dotyczył tylko PDF
        //File.WriteAllBytes(qrPath, new byte[] { 0x89, 0x50, 0x4E, 0x47 }); // minimalny PNG header

        //// Resources/test.jpg też musi istnieć (inaczej wcześniej padnie na LinkedResource)
        //EnsureEmailPhotoExists();

        //Assert.ThrowsAsync<FileNotFoundException>(async () =>
            //await _service.SendEmail("user@example.com", "https://example.com", userEventId, email));
    }


}
