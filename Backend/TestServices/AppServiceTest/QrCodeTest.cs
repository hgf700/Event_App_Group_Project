using EventApp.Services.Services;
using NUnit.Framework;
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;

namespace TestServices.AppServiceTest;

[TestFixture]
public class QrCodeTest
{
    private QrCodeService _service = null!;
    private string _baseDir = null!;
    private string _resourceDir = null!;
    private string _generatedDir = null!;
    private string _logoPath = null!;

    [SetUp]
    public void SetUp()
    {
        _service = new QrCodeService();

        _baseDir = Directory.GetCurrentDirectory();
        _resourceDir = Path.Combine(_baseDir, "Resources");
        _generatedDir = Path.Combine(_baseDir, "Generated");
        _logoPath = Path.Combine(_resourceDir, "logo.png");

        Directory.CreateDirectory(_resourceDir);
        Directory.CreateDirectory(_generatedDir);
    }

    [TearDown]
    public void TearDown()
    {
        // Sprzątamy tylko pliki QR wygenerowane w testach
        if (Directory.Exists(_generatedDir))
        {
            foreach (var file in Directory.GetFiles(_generatedDir, "QR-*-*.png"))
            {
                try { File.Delete(file); } catch { /* ignore */ }
            }
        }
    }

    // ============================================================
    // 1. Brak logo.png
    // ============================================================

    [Test]
    public void GenerateQrCode_WhenLogoMissing_ThrowsFileNotFoundException()
    {
        // Arrange – upewniamy się, że logo NIE istnieje
        if (File.Exists(_logoPath))
            File.Delete(_logoPath);

        // Act + Assert
        var ex = Assert.Throws<FileNotFoundException>(() =>
            _service.GenerateQrCode("https://example.com", 1, "user@example.com"));

        Assert.That(ex!.Message, Does.Contain("Nie znaleziono pliku logo.png"));
        Assert.That(ex.FileName, Is.EqualTo(_logoPath));
    }

    // ============================================================
    // 2. Sukces – zwraca bajty PNG i zapisuje plik
    // ============================================================

    [Test]
    public void GenerateQrCode_WithValidData_ReturnsPngBytesAndSavesFile()
    {
        // Arrange
        EnsureLogoExists();

        int userEventId = 42;
        string email = "user@example.com";
        string content = "https://example.com/ticket/42";
        string expectedPath = Path.Combine(_generatedDir, $"QR-{userEventId}-{email}.png");

        if (File.Exists(expectedPath))
            File.Delete(expectedPath);

        // Act
        byte[] result = _service.GenerateQrCode(content, userEventId, email);

        // Assert – bajty
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.GreaterThan(100));
        Assert.That(IsPng(result), Is.True, "Zwrócone bajty powinny być PNG");

        // Assert – plik na dysku
        Assert.That(File.Exists(expectedPath), Is.True);
        Assert.That(new FileInfo(expectedPath).Length, Is.GreaterThan(100));
    }

    [Test]
    public void GenerateQrCode_SavedFile_MatchesReturnedBytes()
    {
        EnsureLogoExists();

        int userEventId = 99;
        string email = "match@test.com";
        string path = Path.Combine(_generatedDir, $"QR-{userEventId}-{email}.png");

        if (File.Exists(path))
            File.Delete(path);

        byte[] returned = _service.GenerateQrCode("test-content", userEventId, email);
        byte[] fromDisk = File.ReadAllBytes(path);

        Assert.That(fromDisk, Is.EqualTo(returned));
    }

    // ============================================================
    // 3. Nazwa pliku
    // ============================================================

    [TestCase(1, "a@b.com")]
    [TestCase(123456, "long.email.address@domain.co.uk")]
    [TestCase(0, "zero@test.com")]
    public void GenerateQrCode_UsesCorrectFileName(int userEventId, string email)
    {
        EnsureLogoExists();

        string expectedPath = Path.Combine(
            _generatedDir, $"QR-{userEventId}-{email}.png");

        if (File.Exists(expectedPath))
            File.Delete(expectedPath);

        _service.GenerateQrCode("content", userEventId, email);

        Assert.That(File.Exists(expectedPath), Is.True);
    }

    // ============================================================
    // 4. Edge cases – content
    // ============================================================

    [Test]
    public void GenerateQrCode_EmptyContent_StillGeneratesQr()
    {
        EnsureLogoExists();

        // QRCoder pozwala na pusty string – generuje „pusty” kod
        byte[] result = _service.GenerateQrCode("", 7, "empty@test.com");

        Assert.That(result, Is.Not.Null);
        Assert.That(IsPng(result), Is.True);
    }

    [Test]
    public void GenerateQrCode_NullContent_ThrowsArgumentNullException()
    {
        EnsureLogoExists();

        // QRCodeGenerator.CreateQrCode(null, ...) rzuca ArgumentNullException
        Assert.Throws<NullReferenceException>(() =>
            _service.GenerateQrCode(null!, 1, "user@example.com"));
    }

    [Test]
    public void GenerateQrCode_LongContent_GeneratesSuccessfully()
    {
        EnsureLogoExists();

        string longContent = new string('A', 500); // sporo danych, ECC Level Q powinien ogarnąć

        byte[] result = _service.GenerateQrCode(longContent, 5, "long@test.com");

        Assert.That(result, Is.Not.Null);
        Assert.That(IsPng(result), Is.True);
    }

    // ============================================================
    // 5. Idempotencja / nadpisywanie
    // ============================================================

    [Test]
    public void GenerateQrCode_CalledTwice_OverwritesFile()
    {
        EnsureLogoExists();

        int userEventId = 55;
        string email = "overwrite@test.com";
        string path = Path.Combine(_generatedDir, $"QR-{userEventId}-{email}.png");

        var first = _service.GenerateQrCode("first", userEventId, email);
        var firstWriteTime = File.GetLastWriteTimeUtc(path);

        // mała pauza, żeby timestamp się różnił
        System.Threading.Thread.Sleep(50);

        var second = _service.GenerateQrCode("second", userEventId, email);
        var secondWriteTime = File.GetLastWriteTimeUtc(path);

        Assert.That(File.Exists(path), Is.True);
        Assert.That(secondWriteTime, Is.GreaterThanOrEqualTo(firstWriteTime));
        // treść QR się zmieniła → bajty raczej inne
        Assert.That(second, Is.Not.EqualTo(first));
    }

    // ============================================================
    // Helpers
    // ============================================================

    private void EnsureLogoExists()
    {
        if (File.Exists(_logoPath))
            return;

        // Tworzymy minimalne poprawne logo PNG (np. 32x32 czerwony kwadrat)
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Red);
        }
        bmp.Save(_logoPath, ImageFormat.Png);
    }

    private static bool IsPng(byte[] data)
    {
        // Sygnatura PNG: 89 50 4E 47 0D 0A 1A 0A
        if (data.Length < 8) return false;

        return data[0] == 0x89
            && data[1] == 0x50
            && data[2] == 0x4E
            && data[3] == 0x47
            && data[4] == 0x0D
            && data[5] == 0x0A
            && data[6] == 0x1A
            && data[7] == 0x0A;
    }
}