using System.Threading;
using System.Windows;

namespace Sniffer
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		private Mutex? mutex;
		private bool ownsMutex;

		protected override void OnStartup(StartupEventArgs e)
		{
			mutex = new Mutex(true, "Sniffer Network Analyzer", out ownsMutex);
			if (!ownsMutex)
			{
				MessageBox.Show("You have already a running instance", "Warning!", MessageBoxButton.OK, MessageBoxImage.Warning);
				Shutdown();
				return;
			}

			base.OnStartup(e);
		}

		protected override void OnExit(ExitEventArgs e)
		{
			if (ownsMutex)
				mutex?.ReleaseMutex();
			mutex?.Dispose();
			base.OnExit(e);
		}
	}
}
