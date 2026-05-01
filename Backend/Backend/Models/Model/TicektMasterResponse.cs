using System.Text.Json.Serialization;

namespace Backend.Models.Model;

public class TicketmasterResponse
{
    [JsonPropertyName("_embedded")]
    public Embedded Embedded { get; set; }

    [JsonPropertyName("page")]
    public PageInfo Page { get; set; }
}

public class PageInfo
{
    [JsonPropertyName("size")]
    public int Size { get; set; }

    [JsonPropertyName("totalElements")]
    public int TotalElements { get; set; }

    [JsonPropertyName("totalPages")]
    public int TotalPages { get; set; }

    [JsonPropertyName("number")]
    public int Number { get; set; }
}


public class Embedded
{
    [JsonPropertyName("events")]
    public List<EventObject> Events { get; set; }
}

public class EventObject
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; }

    [JsonPropertyName("url")]
    public string Url { get; set; }

    [JsonPropertyName("images")]
    public List<Image> Images { get; set; }

    [JsonPropertyName("dates")]
    public Dates Dates { get; set; }

    [JsonPropertyName("_embedded")]
    public EventEmbedded Embedded { get; set; } // np. venue info
}

public class Image
{

    [JsonPropertyName("url")]
    public string Url { get; set; }

}
public class Dates
{
    [JsonPropertyName("start")]
    public Start Start { get; set; }
}

public class Start
{
    [JsonPropertyName("dateTime")]
    public string DateTime { get; set; }
}

public class EventEmbedded
{
    [JsonPropertyName("venues")]
    public List<Venue> Venues { get; set; }
}

public class Venue
{
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("address")]
    public Address Address { get; set; }

    [JsonPropertyName("city")]
    public City City { get; set; }

    [JsonPropertyName("country")]
    public Country Country { get; set; }
}

public class Address
{
    [JsonPropertyName("line1")]
    public string Line1 { get; set; }
}
public class City
{
    [JsonPropertyName("name")]
    public string Name { get; set; }
}

public class Country
{
    [JsonPropertyName("name")]
    public string Name { get; set; }
}
