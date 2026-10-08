using EventApp.Services.Interfaces;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using Twilio.TwiML.Messaging;

namespace EventApp.Services.Services;

public class EmailService : IEmailService
{
    public void SendEmail(string toEmail, string url, int userEventId)
    {
        try
        {
            // Mailtrap SMTP dane z ENV
            string smtpUser = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_USER");
            string smtpPass = Environment.GetEnvironmentVariable("MAILTRAP_SENDER_PASS");

            if (string.IsNullOrEmpty(smtpUser) || string.IsNullOrEmpty(smtpPass))
                throw new Exception("Brakuje zmiennych środowiskowych: MAILTRAP_USER lub MAILTRAP_PASS");

            var fromAddress = new MailAddress("test@example.com", "Mailtrap Test", System.Text.Encoding.UTF8);
            var toAddress = new MailAddress($"{toEmail}", "test email");

            string body = $@"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Twoje wydarzenie</title>
            </head>

            <body style='margin:0; padding:0; background-color:#f4f4f5; font-family:Arial, Helvetica, sans-serif;'>

                <table width='100%' cellpadding='0' cellspacing='0' border='0'>
                    <tr>
                        <td align='center' style='padding:40px 15px;'>

                            <!-- MAIN CARD -->
                            <table width='600' cellpadding='0' cellspacing='0' border='0'
                                   style='max-width:600px; width:100%; background-color:#ffffff; border-radius:16px; overflow:hidden;'>

                                <!-- HEADER -->
                                <tr>
                                    <td style='padding:28px 35px; background-color:#111827;'>

                                        <table width='100%' cellpadding='0' cellspacing='0' border='0'>
                                            <tr>
                                                <td>
                                                    <div style='font-size:13px; color:#9ca3af; text-transform:uppercase; letter-spacing:2px;'>
                                                        EVENT TICKET
                                                    </div>

                                                    <div style='margin-top:8px; font-size:28px; font-weight:bold; color:#ffffff;'>
                                                        Twoje wydarzenie
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>

                                    </td>
                                </tr>

                                <!-- HERO IMAGE -->
                                <tr>
                                    <td>
                                        <img src='cid:EmailPhoto'
                                             alt='Event'
                                             width='600'
                                             style='display:block; width:100%; max-width:600px; height:auto; border:0;' />
                                    </td>
                                </tr>

                                <!-- CONTENT -->
                                <tr>
                                    <td style='padding:35px;'>

                                        <div style='font-size:14px; color:#6b7280; margin-bottom:8px;'>
                                            TWOJE WYDARZENIE
                                        </div>

                                        <div style='font-size:24px; font-weight:bold; color:#111827; margin-bottom:20px;'>
                                            Kliknij poniżej, aby zobaczyć wydarzenie
                                        </div>

                                        <!-- CTA -->
                                        <table cellpadding='0' cellspacing='0' border='0' style='margin-bottom:30px;'>
                                            <tr>
                                                <td align='center' bgcolor='#111827' style='border-radius:8px;'>
                                                    <a href='{url}'
                                                       style='display:inline-block; padding:14px 24px; font-size:15px; font-weight:bold; color:#ffffff; text-decoration:none;'>
                                                        Zobacz wydarzenie →
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>

                                        <!-- URL -->
                                        <div style='font-size:12px; color:#9ca3af; margin-bottom:30px;'>
                                            {url}
                                        </div>

                                        <!-- DIVIDER -->
                                        <table width='100%' cellpadding='0' cellspacing='0' border='0'>
                                            <tr>
                                                <td style='border-top:1px solid #e5e7eb;'></td>
                                            </tr>
                                        </table>

                                        <!-- QR SECTION -->
                                        <table width='100%' cellpadding='0' cellspacing='0' border='0'>
                                            <tr>
                                                <td align='center' style='padding:30px 0 10px;'>

                                                    <div style='font-size:18px; font-weight:bold; color:#111827;'>
                                                        Twój kod QR
                                                    </div>

                                                    <div style='margin-top:7px; font-size:13px; color:#6b7280;'>
                                                        Pokaż ten kod przy wejściu na wydarzenie
                                                    </div>

                                                </td>
                                            </tr>

                                            <tr>
                                                <td align='center' style='padding:20px 0 10px;'>

                                                    <table cellpadding='0' cellspacing='0' border='0'
                                                           style='background:#ffffff; border:1px solid #e5e7eb; border-radius:12px; padding:15px;'>
                                                        <tr>
                                                            <td>
                                                                <img src='cid:QRimage'
                                                                     alt='QR Code'
                                                                     width='200'
                                                                     height='200'
                                                                     style='display:block; width:200px; height:200px; border:0;' />
                                                            </td>
                                                        </tr>
                                                    </table>

                                                </td>
                                            </tr>
                                        </table>

                                    </td>
                                </tr>

                                <!-- FOOTER -->
                                <tr>
                                    <td style='padding:22px 35px; background-color:#f9fafb; border-top:1px solid #e5e7eb;'>

                                        <div style='text-align:center; font-size:12px; color:#9ca3af; line-height:1.5;'>
                                            Ta wiadomość została wygenerowana automatycznie.<br>
                                            Prosimy na nią nie odpowiadać.
                                        </div>

                                    </td>
                                </tr>

                            </table>

                            <!-- OUTSIDE FOOTER -->
                            <table width='600' cellpadding='0' cellspacing='0' border='0'
                                   style='max-width:600px; width:100%;'>
                                <tr>
                                    <td align='center' style='padding:20px 10px; font-size:11px; color:#9ca3af;'>
                                        © 2026
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

            string basePath = Directory.GetCurrentDirectory();

            string resourcesPath = Path.Combine(basePath, "Resources");
            string generatedPath = Path.Combine(basePath, "Generated");

            Directory.CreateDirectory(resourcesPath);
            Directory.CreateDirectory(generatedPath);

            string fileNameEmailPhoto= Path.Combine(resourcesPath, "test.jpg");
            string fileNameLogo = Path.Combine(resourcesPath, "logo.png");

            string fileNamePdf = $"ticket-{userEventId}.pdf";
            string fileNameQr = $"QR-{userEventId}.png";

            string filePathPdf = Path.Combine(generatedPath, fileNamePdf);
            string filePathQr = Path.Combine(generatedPath, fileNameQr);

            Attachment data = new Attachment(filePathPdf, MediaTypeNames.Text.Plain);
            data.TransferEncoding = TransferEncoding.Base64;

            ContentDisposition disposition = data.ContentDisposition;
            disposition.CreationDate = File.GetCreationTime(filePathPdf);
            disposition.ModificationDate = File.GetLastWriteTime(filePathPdf);
            disposition.ReadDate = File.GetLastAccessTime(filePathPdf);

            LinkedResource image = new LinkedResource(fileNameEmailPhoto, MediaTypeNames.Image.Jpeg);
            LinkedResource pngimage = new LinkedResource(filePathQr, MediaTypeNames.Image.Png);

            // ID dla cid
            image.ContentId = "EmailPhoto"; 
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
                    Console.WriteLine("Sent");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
