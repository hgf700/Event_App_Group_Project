using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using Stripe;
using Stripe.Checkout;
using System.Security.Claims;
using System.Text.Json;
using WebApplication1.Areas.Identity.Data;
using WebApplication1.Models;
using WebApplication1.Models.Identity;
using WebApplication1.ProjectSERVICES;

namespace WebApplication1.Controllers
{
    [Route("Event")]
    public class EventController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly HttpClient _httpClient;
        private readonly ApplicationDbContext _context;
        string YOUR_DOMAIN = "https://localhost:7022";
        private readonly QrService _qrService;
        private readonly SmsService _smsservice;
        private readonly EmailService _emailService;
        private readonly OauthRefreshService _OauthRefreshService;

        

        public EventController(
            HttpClient httpClient, 
            ApplicationDbContext context, 
            QrService qrService, 
            SmsService smsservice, 
            EmailService emailService, 
            UserManager<ApplicationUser> userManager,
            OauthRefreshService OauthRefreshService)
        {
            _httpClient = httpClient;
            _context = context;
            _qrService = qrService;
            _smsservice = smsservice;
            _emailService = emailService;
            _userManager = userManager;
            _OauthRefreshService = OauthRefreshService;
        }

        [HttpGet("")]
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 20, string city = null)
        {
            IQueryable<Models.Event> query = _context.Events;

            //await FetchAndSaveEvents();

            if (!string.IsNullOrWhiteSpace(city))
            {
                ViewBag.City = city;
                query = query.Where(e => e.Address.Contains(city) || e.NameOfClub.Contains(city));
            }

            var allEvents = await query.OrderBy(e => e.StartOfEvent).ToListAsync();

            var uniqueEvents = allEvents
                .GroupBy(e => e.NameOfEvent)
                .Select(g => g.First())
                .ToList();

            var totalEvents = uniqueEvents.Count;

            var paginatedEvents = uniqueEvents
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .ToList();

            ViewBag.TotalPages = (int)Math.Ceiling(totalEvents / (double)pageSize);
            ViewBag.CurrentPage = pageNumber;

            return View("Index", paginatedEvents);
        }

        [HttpGet("Details/{id}")]
        public async Task<IActionResult> Details(int id)
        {
            var ev = await _context.Events.FindAsync(id);
            if (ev == null)
            {
                return NotFound("Event nie został znaleziony.");
            }

            return View("Details", ev);
        }

        [HttpPost("BuyTicket/{id}")]
        public async Task<IActionResult> BuyTicket(int id)
        {

            var ev = await _context.Events.FindAsync(id);
            if (ev == null)
                return NotFound();

            StripeConfiguration.ApiKey = Environment.GetEnvironmentVariable("STRIP_SEC_KEY");

            var options = new SessionCreateOptions
            {
                LineItems = new List<SessionLineItemOptions>
                {
                    new SessionLineItemOptions
                    {
                        PriceData = new SessionLineItemPriceDataOptions
                        {
                            Currency = "pln",
                            UnitAmount = 1000, 
                            ProductData = new SessionLineItemPriceDataProductDataOptions
                            {
                                Name = "Bilet na wydarzenie",
                            },
                        },
                        Quantity = 1,
                    },
                },

                Mode = "payment",
                SuccessUrl = $"{YOUR_DOMAIN}/Event/PaymentSuccess?id={id}",
                CancelUrl = $"{YOUR_DOMAIN}/Event/PaymentFailed",
            };
            var service = new SessionService();
            Session session = service.Create(options);

            return Redirect(session.Url); // przekierowuje do strony Stripe Checkout

        }

        [HttpGet("PaymentSuccess")]
        public async Task<IActionResult> PaymentSuccess([FromQuery] int id)
        {
            var ev = await _context.Events.FindAsync(id);
            if (ev == null)
                return NotFound();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            string accessToken;
            try
            {
                accessToken = await _OauthRefreshService.EnsureValidAccessTokenAsync(user.Id);
            }
            catch
            {
                // <<< POPRAWKA: Użyj Redirect zamiast RedirectToPage w kontrolerze MVC >>>
                return Redirect("/Identity/Account/Login"); // lub RedirectToAction("Login", "Account", new { area = "Identity" });
            }

            // Reszta logiki bez zmian
            var userEvent = new UserEvent
            {
                EventId = ev.Id,
                UserId = user.Id
            };
            _context.UserEvents.Add(userEvent);
            await _context.SaveChangesAsync();

            _qrService.GenerateQrCode(ev.UrlOfEvent);

            bool.TryParse(Environment.GetEnvironmentVariable("TWILIO_SMS_SEND_STATE"), out bool twilio_sms_state);
            if (twilio_sms_state)
            {
                _smsservice.SendSMS(ev.UrlOfEvent);
            }

            var doc = new InvoiceDocument(
                eventName: ev.NameOfEvent,
                eventDate: ev.StartOfEvent.ToString(),
                eventAddress: ev.Address,
                eventType: ev.TypeOfEvent
            );

            string resourcesPath = Path.Combine(Directory.GetCurrentDirectory(), "Resources");
            Directory.CreateDirectory(resourcesPath); // na wszelki wypadek
            string pdfPath = Path.Combine(resourcesPath, "bilet.pdf");
            doc.GeneratePdf(pdfPath);

            string docelowyemail = Environment.GetEnvironmentVariable("TARGET_EMAIL");
            _emailService.SendEmail(docelowyemail, ev.UrlOfEvent);

            ViewBag.Message = "Płatność zakończona sukcesem!";
            return View("Success");
        }


        [HttpGet("PaymentFailed")]
        public IActionResult PaymentFailed()
        {
            // Logika po nieudanej płatności
            ViewBag.Message = "Płatność nie powiodła się. Spróbuj ponownie.";
            return View("Failed"); // Zwróć widok "Failed.cshtml"
        }

        [HttpGet("SearchRequiredEvent")]
        public async Task<IActionResult> SearchRequiredEvent(string city, int pageNumber = 1)
        {

            if (string.IsNullOrWhiteSpace(city))
                return BadRequest("Miasto jest wymagane.");


            try
            {
                string apiKey = Environment.GetEnvironmentVariable("TICKETMASTER_API_KEY");
                if (string.IsNullOrWhiteSpace(apiKey))
                    return StatusCode(500, "Brak klucza API");

                string baseUrl = "https://app.ticketmaster.com/discovery/v2/events.json";
                var query = new Dictionary<string, string>
                {
                    { "apikey", apiKey },
                    { "size", "20" },
                    { "city", city },
                    { "page", (pageNumber - 1).ToString() } // Ticketmaster uses 0-based indexing
                };

                string url = QueryHelpers.AddQueryString(baseUrl, query);
                HttpResponseMessage response = await _httpClient.GetAsync(url).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                    return StatusCode((int)response.StatusCode, "Błąd podczas pobierania danych z Ticketmaster API");

                string json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                var ticketmasterData = JsonSerializer.Deserialize<TicketmasterResponse>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                var externalEvents = ticketmasterData?.Embedded?.Events;

                if (externalEvents == null || !externalEvents.Any())
                    return NotFound("Nie znaleziono wydarzeń.");

                var existingEventIds = _context.Events
                    .AsNoTracking()
                    .Select(e => e.NameOfEvent)
                    .ToHashSet();

                var newEvents = externalEvents
                    .Where(ev => !existingEventIds.Contains(ev.Id))
                    .Select(ev =>
                    {
                        var venue = ev.Embedded?.Venues?.FirstOrDefault();

                        return new WebApplication1.Models.Event
                        {
                            ExternalEventId = ev.Id,
                            TypeOfEvent = ev.Type,
                            NameOfEvent = ev.Name,
                            UrlOfEvent = ev.Url,
                            PhotoUrl = ev.Images?.FirstOrDefault()?.Url,
                            StartOfEvent = DateTime.TryParse(ev.Dates?.Start?.DateTime, out var start) ? start : DateTime.MinValue,
                            Address = venue?.Address?.Line1,
                            City = venue?.City?.Name,
                            Country = venue?.Country?.Name,
                            NameOfClub = venue?.Name,
                        };
                    })
                    .ToList();

                if (newEvents.Any())
                {
                    _context.Events.AddRange(newEvents);
                    await _context.SaveChangesAsync().ConfigureAwait(false);
                }

                // Dodaj ViewBag do paginacji
                ViewBag.City = city;
                ViewBag.CurrentPage = pageNumber;
                ViewBag.TotalPages = ticketmasterData?.Page?.TotalPages ?? 1;

                return View("Index", newEvents);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Wystąpił błąd: {ex.Message}");
            }
        }

                [HttpPost("SaveEvent")]
        public async Task<IActionResult> SaveEvent(int id)
        {
            var ev = await _context.Events.FindAsync(id);
            if (ev == null)
                return NotFound();

            // Tu można dodać logikę zapisywania eventu do profilu użytkownika
            TempData["Message"] = $"Event \"{ev.NameOfEvent}\" został zapisany.";
            return RedirectToAction("Details", new { id });
        }
    }
}