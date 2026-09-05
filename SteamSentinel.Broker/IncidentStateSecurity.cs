using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal interface IIncidentStateSecurity
{
    void EnsureProtectedPath(string path);
    void EnsureProtectedSubtree(string path);
}

internal sealed class WindowsIncidentStateSecurity : IIncidentStateSecurity
{
    public void EnsureProtectedPath(string path) => MachineStateSecurity.EnsureProtectedPath(path);
    public void EnsureProtectedSubtree(string path) => MachineStateSecurity.EnsureProtectedSubtree(path);
}
