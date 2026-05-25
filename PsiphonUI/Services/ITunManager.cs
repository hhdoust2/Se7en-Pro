using System;
using System.Threading.Tasks;

namespace PsiphonUI.Services;

public interface ITunManager : IAsyncDisposable
{
    TunState State { get; }

    string? LastError { get; }

    event EventHandler? StateChanged;
}

public enum TunState
{
    Off,
    Starting,
    Running,
    Stopping,
    Error,
}
