using System.Windows;

namespace Sniffer.Forms
{
	public enum QuitMode
	{
		Exit,
		Cancel
	}

	/// <summary>
	/// Interaction logic for QuitWindow.xaml
	/// </summary>
	public partial class QuitWindow : Window
	{
		private QuitMode mode;
		public QuitMode Mode { get { return mode; } }

		public QuitWindow()
		{
			InitializeComponent();
		}

		private void btnExit_Click(object sender, RoutedEventArgs e)
		{
			mode = QuitMode.Exit;
			this.Close();
		}

		private void btnCancel_Click(object sender, RoutedEventArgs e)
		{
			mode = QuitMode.Cancel;
			this.Close();
		}
	}
}
