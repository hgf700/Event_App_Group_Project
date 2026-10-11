using EventApp.Services.Interfaces;
using QRCoder;
using System.Drawing;
using System.Drawing.Imaging;

namespace EventApp.Services.Services;

public class QrCodeService : IQrCodeService
{
    public byte[] GenerateQrCode(string content, int userEventId)
    {
        string baseDir = Directory.GetCurrentDirectory();
        string resourceDir = Path.Combine(baseDir, "Resources");
        string generatedDir = Path.Combine(baseDir, "Generated");

        Directory.CreateDirectory(resourceDir);
        Directory.CreateDirectory(generatedDir);

        string outputPath = Path.Combine(generatedDir, $"QR-{userEventId}.png");
        string logoPath = Path.Combine(resourceDir, "logo.png");

        if (!File.Exists(logoPath))
            throw new FileNotFoundException("Nie znaleziono pliku logo.png", logoPath);

        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(content, QRCodeGenerator.ECCLevel.Q);

        using var icon = (Bitmap)Image.FromFile(logoPath);
        using var qrCode = new QRCode(qrCodeData);

        using var qrCodeImage = qrCode.GetGraphic(
            pixelsPerModule: 5,
            darkColor: Color.FromArgb(0, 0, 255),
            lightColor: Color.FromArgb(255, 0, 0),
            icon: icon,
            iconSizePercent: 20,
            iconBorderWidth: 1,
            drawQuietZones: true
        );

        qrCodeImage.Save(outputPath, ImageFormat.Png);

        using var stream = new MemoryStream();
        qrCodeImage.Save(stream, ImageFormat.Png);
        return stream.ToArray();
    }
}