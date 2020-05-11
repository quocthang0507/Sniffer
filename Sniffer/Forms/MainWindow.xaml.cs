using Sniffer.Forms;
using SnifferLib;
using System;
using System.Windows;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        SnifferClass snifferClass;

        public MainWindow()
        {
            InitializeComponent();
        }

        public MainWindow(SnifferClass snifferClass)
        {
            this.snifferClass = snifferClass;
            InitializeComponent();
            GetInterface();
            GetComputerName();
            GetTotalPackets();
            GetTotalDisplayedPackets();
        }

        private void btnExit_Click(object sender, RoutedEventArgs e)
        {
            QuitWindow quitWindow = new QuitWindow();
            quitWindow.ShowDialog();
            if (quitWindow.Mode != QuitMode.Cancel)
                Application.Current.Shutdown();
        }

        private void btnAbout_Click(object sender, RoutedEventArgs e)
        {

        }

        private void btnDoc_Click(object sender, RoutedEventArgs e)
        {

        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            QuitWindow quitWindow = new QuitWindow();
            quitWindow.ShowDialog();
            if (quitWindow.Mode == QuitMode.Cancel)
                e.Cancel = true;
            else if (quitWindow.Mode == QuitMode.ExitWithoutSave)
            {
                Application.Current.Shutdown();
            }
            else
            {
                Application.Current.Shutdown();
            }
        }

        public void GetInterface()
        {
            tbxAdapter.Content = snifferClass.GetNameInterface();
        }

        public void GetComputerName()
        {
            tbxComputerName.Content = Environment.MachineName.ToString();
        }

        public void GetTotalPackets()
        {
            tbxTotalPackets.Content = dgPackets.Items.Count;
        }

        public void GetTotalDisplayedPackets()
        {
            tbxTotalDisPackets.Content = dgPackets.Items.Count;
        }
    }
}
