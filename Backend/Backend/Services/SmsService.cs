using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace Backend.Services;

public class SmsService
{
    public void SendSMS(string url)
    {
        bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilio_sms_state);

        if (twilio_sms_state == true)
        {
            string twilio_sid = Environment.GetEnvironmentVariable("TWILIO_SID");
            string twilio_token = Environment.GetEnvironmentVariable("TWILIO_TOKEN");
            string sms_receiver = Environment.GetEnvironmentVariable("SMS_RECEIVER");
            string twilio_number = Environment.GetEnvironmentVariable("TWILIO_NUMBER");

            TwilioClient.Init(twilio_sid, twilio_token);

            var message = MessageResource.Create(
                body: $"Zapisałeś się na event {url}",
                from: new Twilio.Types.PhoneNumber($"{twilio_number}"),
                to: new Twilio.Types.PhoneNumber($"{sms_receiver}")
            );

            Console.WriteLine(message.Body);
        }
    }
}
