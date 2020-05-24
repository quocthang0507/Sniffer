using System.Windows;

namespace Sniffer.Forms
{
    public enum QuitMode
    {
        Save,
        ExitWithoutSave,
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

        private void btnSave_Click(object sender, RoutedEventArgs e)
        {
            mode = QuitMode.Save;
            this.Close();
        }

        private void btnExitWithoutSave_Click(object sender, RoutedEventArgs e)
        {
            mode = QuitMode.ExitWithoutSave;
            this.Close();
        }

        private void btnCancel_Click(object sender, RoutedEventArgs e)
        {
            mode = QuitMode.Cancel;
            this.Close();
        }
    }
}
