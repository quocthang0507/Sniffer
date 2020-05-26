using SnifferLib;
using System.Windows;

namespace Sniffer.Forms
{
	/// <summary>
	/// Interaction logic for WelcomeWindow.xaml
	/// </summary>
	public partial class WelcomeWindow : Window
	{
		private SnifferClass snifferClass;

		public WelcomeWindow()
		{
			InitializeComponent();
			snifferClass = new SnifferClass();
			ShowInterfaces();
		}

		private void ShowInterfaces()
		{
			listInterface.ItemsSource = snifferClass.GetInterfaces();
		}

		private void listInterface_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
		{
			snifferClass.GetInterface(this.listInterface.SelectedIndex);
			this.Hide();
			MainWindow mainWindow = new MainWindow(snifferClass);
			mainWindow.Show();
		}
	}
}
