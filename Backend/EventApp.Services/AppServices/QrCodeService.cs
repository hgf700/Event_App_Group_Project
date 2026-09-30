using EventApp.Services.Interfaces;
using QRCoder;
using System.Drawing;

namespace EventApp.Services.Services;

//public class QrCodeService
//{
//    public void GenerateQrCode(string url)
//    {
//        try
//        {
//            string baseDir = Directory.GetCurrentDirectory();
//            string resourceDir = Path.Combine(baseDir, "Resources");
//            Directory.CreateDirectory(resourceDir);

//            string outputPath = Path.Combine(resourceDir, "QR.png");

//            using var qrGenerator = new QRCodeGenerator();
//            using var qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
//            using var qrCode = new PngByteQRCode(qrCodeData);
//            var qrBytes = qrCode.GetGraphic(20); // 20 pixels per module

//            File.WriteAllBytes(outputPath, qrBytes);
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine(ex.Message);
//        }
//    }
//}


//public void GenerateQrCode(string url)
//    {
//        string baseDir = Directory.GetCurrentDirectory();
//        string resourceDir = Path.Combine(baseDir, "Resources");

//        // Upewnij się, że folder Resources istniej

//        // Pełna ścieżka do pliku logo
//        string logoPath = Path.Combine(resourceDir, "logo.PNG");

//        if (!File.Exists(logoPath))
//        {
//            throw new FileNotFoundException("Nie znaleziono pliku logo.PNG", logoPath);
//        }

//        // Ścieżka do wygenerowanego pliku QR
//        string outputPath = Path.Combine(resourceDir, "QR.PNG");

//        QRCodeGenerator qrGenerator = new QRCodeGenerator();
//        QRCodeData qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);

//        Bitmap icon = (Bitmap)Image.FromFile(logoPath);

//        QRCode qrCode = new QRCode(qrCodeData);
//        Bitmap qrCodeImage = qrCode.GetGraphic(
//            pixelsPerModule: 5,
//            darkColor: Color.FromArgb(0, 0, 255),
//            lightColor: Color.FromArgb(255, 0, 0),
//            icon: icon,
//            iconSizePercent: 20,
//            iconBorderWidth: 20,
//            drawQuietZones: true
//        );

//        qrCodeImage.Save(outputPath, ImageFormat.Png);
//    }

public class QrCodeService : IQrCodeService
{
    public byte[] GenerateQrCodeBytes(string content)
    {
        using var qrGenerator = new QRCodeGenerator();

        var qrCodeData = qrGenerator.CreateQrCode(
            content,
            QRCodeGenerator.ECCLevel.Q);

        var qrCode = new PngByteQRCode(qrCodeData);

        return qrCode.GetGraphic(10);
    }
}