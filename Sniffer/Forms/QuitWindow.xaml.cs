using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Sniffer.Forms
{
	/// <summary>
	/// Interaction logic for QuitWindow.xaml
	/// </summary>
	public partial class QuitWindow : Window
	{
		public QuitWindow()
		{
			InitializeComponent();
		}

		private void btnSave_Click(object sender, RoutedEventArgs e)
		{

		}

		private void btnExitWithoutSave_Click(object sender, RoutedEventArgs e)
		{
			Environment.Exit(1);
		}

		private void btnCancel_Click(object sender, RoutedEventArgs e)
		{
			this.Close();
		}
	}
}
