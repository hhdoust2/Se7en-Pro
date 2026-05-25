using System.Diagnostics;
using System.Reflection;
using CommunityToolkit.Mvvm.Input;

namespace PsiphonUI.ViewModels;

public sealed partial class AboutViewModel : PageViewModelBase
{
    public override string Title => "About";
    public override string Route => "about";
    public override string Icon => "InformationOutline";

    public string AppName => "PsiphonUI";
    public string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.1";
    public string Copyright => "Built on Psiphon 3 (GPLv3). Modern UI by PsiphonUI.";

    [RelayCommand]
    private static void OpenInfoLink() =>
        OpenUrl("https://psiphon.ca/");

    [RelayCommand]
    private static void OpenFaq() =>
        OpenUrl("https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/faq.html");

    [RelayCommand]
    private static void OpenPrivacy() =>
        OpenUrl("https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/privacy.html#information-collected");

    [RelayCommand]
    private static void OpenGitHub() =>
        OpenUrl("https://github.com/KNG7-P/Se7en-Pro");

    private static void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {

        }
    }
}
