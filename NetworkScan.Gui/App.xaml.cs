using System.Windows;
using System.IO;
using System;
using System.Threading.Tasks;

namespace NetworkScan.Gui;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        SetupGlobalErrorHandlers();
        base.OnStartup(e);
    }

    private void SetupGlobalErrorHandlers()
    {
        this.DispatcherUnhandledException += (s, ev) =>
        {
            LogAndShow(ev.Exception, "DispatcherUnhandledException");
            ev.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (s, ev) =>
        {
            var ex = ev.ExceptionObject as Exception ?? new Exception("Unknown unhandled exception");
            LogAndShow(ex, "AppDomain.UnhandledException");
        };
        TaskScheduler.UnobservedTaskException += (s, ev) =>
        {
            // These are often benign (e.g., socket aborts when we cancel/timeout).
            // Log them silently to avoid noisy popups during scans.
            LogOnly(ev.Exception, "TaskScheduler.UnobservedTaskException");
            ev.SetObserved();
        };
    }

    private void LogAndShow(Exception ex, string source)
    {
        try
        {
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gui_crash.log");
            File.AppendAllText(path, $"[{DateTime.Now:u}] {source}: {ex}\n\n");
        }
        catch { }
        MessageBox.Show($"{source}: {ex.Message}\nSee gui_crash.log for details.", "NetworkScan GUI Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void LogOnly(Exception ex, string source)
    {
        try
        {
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "gui_crash.log");
            File.AppendAllText(path, $"[{DateTime.Now:u}] {source}: {ex}\n\n");
        }
        catch { }
    }
}


