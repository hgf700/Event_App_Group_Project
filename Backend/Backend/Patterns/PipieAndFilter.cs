using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Backend.Patterns;

public class StringContext
{
    public string? Value { get; set; }
}

public interface IFilter
{
    StringContext Execute(StringContext input);
}

public class TrimFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        input.Value = input.Value?.Trim();
        return input;
    }
}

public class ToLowerInvariantFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        input.Value = input.Value?.ToLowerInvariant();
        return input;
    }
}

//szybciej niż regex
public class WhitespacesFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        input.Value = string.Join(" ",
            (input.Value ?? "").
            Split(' ', StringSplitOptions.RemoveEmptyEntries));
        return input;
    }
}


// if value nothing then if random whitespace(\s) (+) more than 1 replace to space(" ")
//Regex = wolniejszy niż string ops przy dużym ruchu → koszt CPU
public class RegexWhitespacesFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        input.Value = Regex.Replace(input.Value ?? "", @"\s+", " ");
        return input;
    }
}

public class Pipe
{
    private readonly List<IFilter> _filters = new();

    public Pipe Add(IFilter filter)
    {
        _filters.Add(filter);
        return this;
    }

    public StringContext Execute(StringContext input)
    {
        var result = input;

        foreach (var filter in _filters)
            result = filter.Execute(result);

        return result;
    }
}