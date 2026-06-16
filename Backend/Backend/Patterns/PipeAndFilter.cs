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
        return new StringContext
        {
            Value = input.Value?.Trim()
        };
    }
}

public class ToLowerInvariantFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        return new StringContext
        {
            Value = input.Value?.ToLowerInvariant()
        };
    }
}

public class EmptyIfNullOrWhitespaceFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        return new StringContext
        {
            Value = string.IsNullOrWhiteSpace(input.Value)
                ? string.Empty
                : input.Value
        };
    }
}

public class NormalizeWhitespaceFilter : IFilter
{
    public StringContext Execute(StringContext input)
    {
        var value = input.Value;

        return new StringContext
        {
            Value = string.Join(" ",
                value?.Split((char[])null, StringSplitOptions.RemoveEmptyEntries)
                ?? Array.Empty<string>())
        };
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
        var result = input ?? new StringContext { Value = string.Empty };

        foreach (var filter in _filters)
            result = filter.Execute(result);

        return result;
    }
}