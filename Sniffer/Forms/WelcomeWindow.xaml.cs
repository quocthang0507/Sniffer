using SnifferLib;
using System;
using System.Windows;
using System.Windows.Input;

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
			snifferClass = SnifferClass.getInstance();
			ShowInterfaces();
		}

		private void ShowInterfaces()
		{
			try
			{
				listInterface.ItemsSource = snifferClass.ListNameDevices;
			}
			catch (Exception e)
			{
				MessageBox.Show(e.Message, "Có lỗi xảy ra!", MessageBoxButton.OK, MessageBoxImage.Error);
				this.Close();
			}

		}

		private void listInterface_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
		{
			HandleSelection();
		}

		private void HandleSelection()
		{
			if (this.listInterface.SelectedIndex != -1)
			{
				try
				{
					snifferClass.SetSelectedInterface(this.listInterface.SelectedIndex);
				}
				catch (Exception e)
				{
					MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
					return;
				}
				this.Hide();
				MainWindow mainWindow = new MainWindow(snifferClass);
				mainWindow.Show();
			}
		}

		private void listInterface_KeyDown(object sender, KeyEventArgs e)
		{
			if (e.Key == Key.Enter)
			{
				HandleSelection();
			}
		}
	}
}
