using QRCoder;

namespace Backend.Services;

public class QrCodeService
{
    public void GenerateQrCode(string url)
    {
        try
        {
            string baseDir = Directory.GetCurrentDirectory();
            string resourceDir = Path.Combine(baseDir, "Resources");
            Directory.CreateDirectory(resourceDir);

            string outputPath = Path.Combine(resourceDir, "QR.png");

            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrBytes = qrCode.GetGraphic(20); // 20 pixels per module

            File.WriteAllBytes(outputPath, qrBytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
