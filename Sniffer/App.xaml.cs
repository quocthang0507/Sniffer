using System.Threading;
using System.Windows;

namespace Sniffer
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		Mutex mutex;

		protected override void OnStartup(StartupEventArgs e)
		{
			bool isNewInstance = false;
			mutex = new Mutex(true, "Sniffer Network Analyzer", out isNewInstance);
			if (!isNewInstance)
			{
				MessageBox.Show("You have already a running instance", "Warning!", MessageBoxButton.OK, MessageBoxImage.Warning);
				App.Current.Shutdown();
			}
		}
	}
}
