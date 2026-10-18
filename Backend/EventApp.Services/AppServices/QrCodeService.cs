using AngleSharp.Media;
using EventApp.Services.Interfaces;
using QRCoder;
using SkiaSharp;

namespace EventApp.Services.Services;

public class QrCodeService : IQrCodeService
{
    public byte[] GenerateQrCode(string content, int userEventId, string email)
    {
        if (content is null)
            throw new ArgumentNullException(nameof(content));

        string baseDir = Directory.GetCurrentDirectory();
        string resourceDir = Path.Combine(baseDir, "Resources");
        string generatedDir = Path.Combine(baseDir, "Generated");

        Directory.CreateDirectory(resourceDir);
        Directory.CreateDirectory(generatedDir);

        string outputPath = Path.Combine(generatedDir, $"QR-{userEventId}-{email}.png");
        string logoPath = Path.Combine(resourceDir, "logo.png");

        if (!File.Exists(logoPath))
            throw new FileNotFoundException("Nie znaleziono pliku logo.png", logoPath);

        // 1. Generujemy dane QR
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(content, QRCodeGenerator.ECCLevel.Q);

        // 2. Renderujemy QR do PNG (bez System.Drawing)
        var pngQr = new PngByteQRCode(qrCodeData);
        byte[] qrBytes = pngQr.GetGraphic(pixelsPerModule: 8); // możesz zmienić wielkość

        // 3. Nakładamy logo na środek przy pomocy SkiaSharp
        using var qrBitmap = SKBitmap.Decode(qrBytes);
        using var logoBitmap = SKBitmap.Decode(logoPath);

        int logoSize = (int)(qrBitmap.Width * 0.20); // 20% jak wcześniej
        int logoX = (qrBitmap.Width - logoSize) / 2;
        int logoY = (qrBitmap.Height - logoSize) / 2;

        using var surface = SKSurface.Create(new SKImageInfo(qrBitmap.Width, qrBitmap.Height));
        var canvas = surface.Canvas;

        // Rysujemy QR
        canvas.DrawBitmap(qrBitmap, 0, 0);

        // Opcjonalnie białe tło pod logo (dla lepszej czytelności)
        using var backgroundPaint = new SKPaint
        {
            Color = SKColors.White,
            Style = SKPaintStyle.Fill,
            IsAntialias = true
        };
        float padding = 4;
        canvas.DrawRoundRect(
            logoX - padding,
            logoY - padding,
            logoSize + padding * 2,
            logoSize + padding * 2,
            8, 8,
            backgroundPaint);

        // Rysujemy logo
        var destRect = new SKRect(logoX, logoY, logoX + logoSize, logoY + logoSize);
        canvas.DrawBitmap(logoBitmap, destRect);

        // 4. Zapisujemy wynik
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        byte[] result = data.ToArray();

        File.WriteAllBytes(outputPath, result);

        return result;
    }
}