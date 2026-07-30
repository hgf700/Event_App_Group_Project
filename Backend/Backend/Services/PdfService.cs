using QRCoder;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using static QRCoder.PayloadGenerator;

namespace Backend.Services;

public class InvoiceDocument : IDocument
{
    public string EventName { get; set; }
    public string EventDate { get; set; }
    public string EventAddress { get; set; }
    public string EventType { get; set; }
    public string EventUrl { get; set; }

    private readonly byte[] _qrCode;

    public InvoiceDocument(
        string eventName,
        string eventDate,
        string eventAddress,
        string eventType,
        string eventUrl,
        byte[] qrCode)
    {
        EventName = eventName;
        EventDate = eventDate;
        EventAddress = eventAddress;
        EventType = eventType;
        EventUrl = eventUrl;
        _qrCode = qrCode;
    }

    public DocumentSettings GetSettings() => DocumentSettings.Default;

    public void Compose(IDocumentContainer container)
    {
        try
        {
            container
                .Page(page =>
                {
                    page.Margin(50);
                    page.Size(PageSizes.A4);

                    page.Header().Element(ComposeHeader);
                    page.Content().Element(ComposeContent);
                });
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    void ComposeHeader(IContainer container)
    {
        try
        {
            container.Row(row =>
            {
                row.RelativeItem().Column(col =>
                {
                    col.Item().Text("Potwierdzenie zakupu biletu")
                        .FontSize(20)
                        .SemiBold()
                        .FontColor(Colors.Blue.Darken2);
                });

                // Można tu wstawić logo z Resources, jeśli chcesz
                row.ConstantItem(100).Height(50).Placeholder();
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }

    void ComposeContent(IContainer container)
    {
        try
        {
            container.PaddingVertical(30).Column(col =>
            {
                col.Spacing(15);

                col.Item().Text($"Wydarzenie: {EventName}")
                    .FontSize(14);

                col.Item().Text($"Address: {EventAddress}")
                    .FontSize(14);

                col.Item().Text($"Data wydarzenia: {EventDate}")
                    .FontSize(14);

                col.Item().Text($"Typ wydarzenia: {EventType}")
                    .FontSize(14);

                col.Item().PaddingTop(200).Row(row =>
                {

                    row.RelativeItem(); // lewa pusta przestrzeń

                    row.ConstantItem(300).Height(300).Image(_qrCode).FitArea();

                    row.RelativeItem(); // prawa pusta przestrzeń
                });

            });
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}


