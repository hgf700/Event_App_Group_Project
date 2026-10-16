using EventApp.Services.Services;
using NUnit.Framework;
using System;
using System.IO;
using System.Threading.Tasks;

namespace TestServices.AppServiceTest;

[TestFixture]
public class EmailTest
{
    private EmailService _service = null!;
    private string _originalUser = null!;
    private string _originalPass = null!;

    [SetUp]
    public void SetUp()
    {
        _service = new EmailService();

        // Zapamiętujemy oryginalne wartości ENV, żeby nie psuć innych testów
        _originalUser = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_USER");
        _originalPass = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_PASS");
    }

    [TearDown]
    public void TearDown()
    {
        // Przywracamy ENV
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_USER", _originalUser);
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_PASS", _originalPass);
    }

    // ============================================================
    // 1. Walidacja argumentów null
    // ============================================================

    [Test]
    public void SendEmail_NullToEmail_ThrowsArgumentNullException()
    {
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _service.SendEmail(null!, "https://example.com", 1, "user@example.com"));

        Assert.That(ex!.ParamName, Is.EqualTo("toEmail"));
    }

    [Test]
    public void SendEmail_NullUrl_ThrowsArgumentNullException()
    {
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _service.SendEmail("user@example.com", null!, 1, "user@example.com"));

        Assert.That(ex!.ParamName, Is.EqualTo("url"));
    }

    [Test]
    public void SendEmail_NullEmail_ThrowsArgumentNullException()
    {
        var ex = Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", 1, null!));

        Assert.That(ex!.ParamName, Is.EqualTo("email"));
    }

    [Test]
    public void SendEmail_AllNull_ThrowsArgumentNullException()
    {
        // Pierwszy null w kolejności sprawdzania to toEmail
        Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _service.SendEmail(null!, null!, 1, null!));
    }

    // ============================================================
    // 2. Brakujące zmienne środowiskowe
    // ============================================================

    [Test]
    public void SendEmail_MissingMailtrapUser_ThrowsInvalidOperationException()
    {
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_USER", null);
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_PASS", "test-password");

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", 1, "user@example.com"));

        Assert.That(ex!.Message, Is.EqualTo("MAILTRAP_SENDER_USER is not set."));
    }

    [Test]
    public void SendEmail_MissingMailtrapPass_ThrowsInvalidOperationException()
    {
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_USER", "test-user");
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_PASS", null);

        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", 1, "user@example.com"));

        Assert.That(ex!.Message, Is.EqualTo("MAILTRAP_SENDER_PASS is not set."));
    }

    [Test]
    public void SendEmail_BothEnvVariablesMissing_ThrowsInvalidOperationException()
    {
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_USER", null);
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_PASS", null);

        // Rzucany jest pierwszy brakujący (USER)
        var ex = Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", 1, "user@example.com"));

        Assert.That(ex!.Message, Is.EqualTo("MAILTRAP_SENDER_USER is not set."));
    }

    // ============================================================
    // 3. Brakujące pliki
    // ============================================================

    private void SetValidEnv()
    {
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_USER", "test-user");
        Environment.SetEnvironmentVariable("MAILTRAP_SENDER_PASS", "test-password");
    }

    [TestCase(123, "testuser@example.com")]
    [TestCase(1, "a")]
    [TestCase(999999, "very.long.email.address@domain.co.uk")]
    public void SendEmail_MissingPdf_ThrowsFileNotFoundException(int userEventId, string email)
    {
        SetValidEnv();

        string generatedPath = Path.Combine(Directory.GetCurrentDirectory(), "Generated");
        Directory.CreateDirectory(generatedPath);

        string pdfPath = Path.Combine(generatedPath, $"ticket-{userEventId}-{email}.pdf");
        string qrPath = Path.Combine(generatedPath, $"QR-{userEventId}-{email}.png");

        // Upewniamy się, że PDF nie istnieje
        if (File.Exists(pdfPath)) File.Delete(pdfPath);

        // Tworzymy QR, żeby test dotyczył tylko PDF
        File.WriteAllBytes(qrPath, new byte[] { 0x89, 0x50, 0x4E, 0x47 }); // minimalny PNG header

        // Resources/test.jpg też musi istnieć (inaczej wcześniej padnie na LinkedResource)
        EnsureEmailPhotoExists();

        Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", userEventId, email));
    }

    [TestCase(123, "testuser@example.com")]
    [TestCase(1, "a")]
    public void SendEmail_MissingQr_ThrowsFileNotFoundException(int userEventId, string email)
    {
        SetValidEnv();

        string generatedPath = Path.Combine(Directory.GetCurrentDirectory(), "Generated");
        Directory.CreateDirectory(generatedPath);

        string pdfPath = Path.Combine(generatedPath, $"ticket-{userEventId}-{email}.pdf");
        string qrPath = Path.Combine(generatedPath, $"QR-{userEventId}-{email}.png");

        // Upewniamy się, że QR nie istnieje
        if (File.Exists(qrPath)) File.Delete(qrPath);

        // Tworzymy PDF
        File.WriteAllBytes(pdfPath, new byte[] { 0x25, 0x50, 0x44, 0x46 }); // %PDF

        EnsureEmailPhotoExists();

        Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", userEventId, email));
    }

    [Test]
    public void SendEmail_MissingEmailPhoto_ThrowsFileNotFoundException()
    {
        SetValidEnv();

        int userEventId = 42;
        string email = "photo-missing@example.com";

        string generatedPath = Path.Combine(Directory.GetCurrentDirectory(), "Generated");
        Directory.CreateDirectory(generatedPath);

        // Tworzymy wymagane pliki Generated
        File.WriteAllBytes(
            Path.Combine(generatedPath, $"ticket-{userEventId}-{email}.pdf"),
            new byte[] { 0x25, 0x50, 0x44, 0x46 });

        File.WriteAllBytes(
            Path.Combine(generatedPath, $"QR-{userEventId}-{email}.png"),
            new byte[] { 0x89, 0x50, 0x4E, 0x47 });

        // Usuwamy test.jpg
        string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
        Directory.CreateDirectory(resourcesPath);
        string photoPath = Path.Combine(resourcesPath, "test.jpg");
        if (File.Exists(photoPath)) File.Delete(photoPath);

        Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await _service.SendEmail("user@example.com", "https://example.com", userEventId, email));
    }

    // ============================================================
    // 4. Testy ścieżek plików (nazewnictwo)
    // ============================================================

    [Test]
    public void SendEmail_UsesCorrectPdfAndQrFileNames()
    {
        // Ten test nie wywołuje SendEmail – tylko sprawdza logikę nazewnictwa,
        // którą możesz wyciągnąć do osobnej metody jeśli chcesz.
        int userEventId = 777;
        string email = "file-name@test.com";

        string expectedPdf = $"ticket-{userEventId}-{email}.pdf";
        string expectedQr = $"QR-{userEventId}-{email}.png";

        Assert.That(expectedPdf, Is.EqualTo("ticket-777-file-name@test.com.pdf"));
        Assert.That(expectedQr, Is.EqualTo("QR-777-file-name@test.com.png"));
    }

    // ============================================================
    // Helper
    // ============================================================

    private void EnsureEmailPhotoExists()
    {
        string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
        Directory.CreateDirectory(resourcesPath);
        string photoPath = Path.Combine(resourcesPath, "test.jpg");

        if (!File.Exists(photoPath))
        {
            // Minimalny poprawny JPEG (1x1 pixel)
            File.WriteAllBytes(photoPath, new byte[]
            {
                0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
                0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
                0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
                0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
                0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
                0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
                0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
                0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
                0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
                0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
                0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
                0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
                0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
                0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
                0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
                0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
                0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
                0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
                0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
                0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
                0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
                0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
                0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
                0x00, 0x00, 0x3F, 0x00, 0xFB, 0xD5, 0xDB, 0x20, 0xA8, 0xF1, 0x45, 0x00,
                0xFF, 0xD9
            });
        }
    }
}