using SnifferLib;
using System.Windows;

namespace Sniffer.Forms
{
    /// <summary>
    /// Interaction logic for WelcomeWindow.xaml
    /// </summary>
    public partial class WelcomeWindow : Window
    {
        public WelcomeWindow()
        {
            InitializeComponent();
            ShowInterfaces();
        }
        private void ShowInterfaces()
        {
            listInterface.ItemsSource = SnifferClass.GetInterfaces();
        }
    }
}
