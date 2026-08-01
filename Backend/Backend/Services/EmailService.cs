using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using Twilio.TwiML.Messaging;

namespace Backend.Services;

public class EmailService
{
    public void SendEmail(string toEmail, string url)
    {
        try
        {
            // Mailtrap SMTP dane z ENV
            string smtpUser = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_USER");
            string smtpPass = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_PASS");
            if (string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass))
            {
                throw new Exception("Brakuje zmiennych środowiskowych: MAILTRAP_USER lub MAILTRAP_PASS");
            }

            var fromAddress = new MailAddress("test@example.com", "Mailtrap Test", System.Text.Encoding.UTF8);
            var toAddress = new MailAddress($"{toEmail}", "test email");

            string body = $@"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <title>Email</title>
            </head>

            <body style='margin:0; padding:0; background-color:#f0f0f0; font-family:Arial, sans-serif;'>

                <table width='100%' cellpadding='0' cellspacing='0'>
                    <tr>
                        <td align='center' style='padding:30px;'>

                            <table width='600' cellpadding='0' cellspacing='0' 
                                   style='background:#ffffff; border-radius:8px; padding:30px;'>

                                <tr>
                                    <td align='center'>
                                        <h2 style='color:#333; margin-bottom:20px;'>
                                            Email with event
                                        </h2>
                                    </td>
                                </tr>

                                <tr>
                                    <td style='color:#555; font-size:15px; line-height:1.5;'>

                                        <p>
                                            Kliknij w poniższy link:
                                        </p>

                                        <!-- EVENT URL -->
                                        <p>
                                            <a href='{url}' 
                                               style='color:#0066cc; text-decoration:none;'>
                                                {url}
                                            </a>
                                        </p>

                                        <hr style='border:none; border-top:1px solid #ddd; margin:25px 0;'>

                                        <!-- MAIN IMAGE -->
                                        <div style='text-align:center;'>
                                            <img src='cid:testImage' 
                                                 alt='test'
                                                 style='max-width:100%; height:auto;' />
                                        </div>

                                        <br />

                                        <!-- QR CODE -->
                                        <div style='text-align:center;'>
                                            <img src='cid:QRimage' 
                                                 alt='QR'
                                                 style='width:200px; height:200px;' />
                                        </div>

                                    </td>
                                </tr>

                                <tr>
                                    <td align='center' 
                                        style='padding-top:30px; color:#999; font-size:12px;'>
                                        Wiadomość wygenerowana automatycznie.
                                    </td>
                                </tr>

                            </table>

                        </td>
                    </tr>
                </table>

            </body>
            </html>";

            var plainView = AlternateView.CreateAlternateViewFromString("To jest tekstowa wersja wiadomości", null, "text/plain");
            AlternateView htmlView = AlternateView.CreateAlternateViewFromString(body, null, MediaTypeNames.Text.Html);

            MailAddress bcc = new MailAddress("manager1@contoso.com");
            MailAddress copy = new MailAddress("Notification_List@contoso.com");

            string dir = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
            Directory.SetCurrentDirectory(dir);

            string file = "bilet.pdf";
            // Create  the file attachment for this email message.
            Attachment data = new Attachment(file, MediaTypeNames.Text.Plain);
            data.TransferEncoding = TransferEncoding.Base64;
            // Add time stamp information for the file.
            ContentDisposition disposition = data.ContentDisposition;
            disposition.CreationDate = System.IO.File.GetCreationTime(file);
            disposition.ModificationDate = System.IO.File.GetLastWriteTime(file);
            disposition.ReadDate = System.IO.File.GetLastAccessTime(file);

            string imagePath = Path.Combine("test.jpg");
            LinkedResource image = new LinkedResource(imagePath, MediaTypeNames.Image.Jpeg);

            string pngPath = Path.Combine("QR.PNG");
            LinkedResource pngimage = new LinkedResource(pngPath, MediaTypeNames.Image.Png);

            image.ContentId = "testImage"; // ID dla cid
            image.TransferEncoding = TransferEncoding.Base64;

            pngimage.ContentId = "QRimage";
            pngimage.TransferEncoding = TransferEncoding.Base64;

            htmlView.LinkedResources.Add(image);
            htmlView.LinkedResources.Add(pngimage);

            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = "Testowy temat",
                //Body = body, podwyzsza spam
                SubjectEncoding = System.Text.Encoding.UTF8,
                BodyEncoding = System.Text.Encoding.UTF8,
                IsBodyHtml = true,
                HeadersEncoding = System.Text.Encoding.UTF8,
                Priority = MailPriority.High,
            })
            {
                message.AlternateViews.Add(plainView);
                message.AlternateViews.Add(htmlView);
                message.Attachments.Add(data);
                message.Bcc.Add(bcc);
                message.CC.Add(copy);

                string messageId = $"<{Guid.NewGuid()}@{Dns.GetHostName()}>";

                message.Headers.Add("Message-Id", messageId);
                {
                    var smtp = new SmtpClient
                    {
                        Host = "sandbox.smtp.mailtrap.io",
                        Port = 2525,
                        EnableSsl = true,
                        DeliveryMethod = SmtpDeliveryMethod.Network,
                        Credentials = new NetworkCredential(smtpUser, smtpPass),
                        //Timeout = 20000
                    };

                    smtp.Send(message);
                    System.Console.WriteLine("Sent");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
