using System;
using PsiphonUI.Models;

namespace PsiphonUI.Services;

public interface ITrayIconService : IDisposable
{
    void Initialize();
    void ShowWindow();
    void HideToTray();
    bool IsHidden { get; }
    event EventHandler? RequestShow;
    event EventHandler? RequestExit;
    event EventHandler? RequestToggleConnection;

    /// <summary>
    /// Update the tray icon + tooltip + Connect/Disconnect menu label to
    /// reflect the current tunnel connection state.
    /// </summary>
    void UpdateConnectionState(ConnectionState state);
}
