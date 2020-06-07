﻿using SnifferLib;
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
			snifferClass = new SnifferClass();
			ShowInterfaces();
		}

		private void ShowInterfaces()
		{
			listInterface.ItemsSource = snifferClass.GetInterfaces();
		}

		private void listInterface_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
		{
			HandleSelection();
		}

		private void HandleSelection()
		{
			if (this.listInterface.SelectedIndex != -1)
			{
				snifferClass.GetInterface(this.listInterface.SelectedIndex);
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
