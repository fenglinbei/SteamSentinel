using System.Reflection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>Only the published, typed budget whitelist can be changed during a scan.</summary>
public static class ScanLimitAccess
{
    public static ScanLimitDefinition Definition(string key) => ScanLimitSettings.Fields.SingleOrDefault(f => f.Key == key)
        ?? throw new InvalidDataException("Unknown scan limit.");

    private static (object Owner, PropertyInfo Property) Locate(ScanOptions options, string key)
    {
        _ = Definition(key);
        string[] parts = key.Split('.');
        object owner = options;
        if (parts.Length == 2)
            owner = parts[0] switch
            {
                nameof(ScanOptions.ContainerLimits) => options.ContainerLimits ?? throw new InvalidDataException("Missing container limits."),
                nameof(ScanOptions.RangeLimits) => options.RangeLimits ?? throw new InvalidDataException("Missing range limits."),
                _ => throw new InvalidDataException("Unknown limit owner.")
            };
        return (owner, owner.GetType().GetProperty(parts[^1]) ?? throw new InvalidDataException("Unknown limit property."));
    }

    public static long Get(ScanOptions options, string key)
    {
        var (owner, property) = Locate(options, key);
        return Convert.ToInt64(property.GetValue(owner), System.Globalization.CultureInfo.InvariantCulture);
    }

    public static void ValidateChange(ScanLimitChange change)
    {
        ScanLimitDefinition field = Definition(change.LimitKey);
        if (change.Before < 0 || change.After <= change.Before || change.LimitKey == "ContainerLimits.ReservedDiskBytes")
            throw new InvalidDataException("Resource grants must increase an adjustable upper budget.");
        field.Validate(change.After / field.Scale);
    }

    public static void Apply(ScanOptions options, IReadOnlyList<ScanLimitChange> changes)
    {
        if (changes.Count is < 1 or > 8 || changes.Select(c => c.LimitKey).Distinct().Count() != changes.Count)
            throw new InvalidDataException("Invalid resource grant.");
        List<(object Owner, PropertyInfo Property, object Value)> assignments = [];
        foreach (ScanLimitChange change in changes)
        {
            ValidateChange(change);
            if (Get(options, change.LimitKey) != change.Before) throw new InvalidDataException("Stale resource grant.");
            var (owner, property) = Locate(options, change.LimitKey);
            assignments.Add((owner, property, Convert.ChangeType(change.After, property.PropertyType, System.Globalization.CultureInfo.InvariantCulture)));
        }
        foreach (var assignment in assignments) assignment.Property.SetValue(assignment.Owner, assignment.Value);
        // Keep legacy readers and the graph readers on the same effective limits.
        if (options.ContainerLimits is { } limits)
        {
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumEntryBytes))!.SetValue(options, limits.MaximumEntryBytes);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumExpandedBytes))!.SetValue(options, limits.MaximumExpandedBytes);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumArchiveDepth))!.SetValue(options, limits.MaximumDepth);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumArchiveEntries))!.SetValue(options, limits.MaximumEntries);
            typeof(ScanOptions).GetProperty(nameof(ScanOptions.MaximumCompressionRatio))!.SetValue(options, limits.MaximumCompressionRatio);
        }
        if (options.RangeLimits is { } ranges)
            typeof(ContainerRangeLimits).GetProperty(nameof(ContainerRangeLimits.MaximumDuration))!.SetValue(ranges,
                TimeSpan.FromSeconds(options.MaximumStructureDurationSeconds));
    }
}
