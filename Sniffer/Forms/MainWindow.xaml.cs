using Sniffer.Forms;
using SnifferLib;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Sniffer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private SnifferClass snifferClass;
        private Thread t1;
        private Thread t2;

        public MainWindow()
        {
            InitializeComponent();
            btnStop.IsEnabled = false;
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
                t1.Abort();
                t2.Abort();
                Application.Current.Shutdown();
            }
            else
            {
                t1.Abort();
                t2.Abort();
                Application.Current.Shutdown();
            }
        }

        private void GetInterface()
        {
            tbxAdapter.Content = snifferClass.GetNameInterface();
        }

        private void GetComputerName()
        {
            tbxComputerName.Content = Environment.MachineName.ToString();
        }

        private void GetTotalPackets()
        {
            tbxTotalPackets.Content = dgPackets.Items.Count;
        }

        private void GetTotalDisplayedPackets()
        {
            tbxTotalDisPackets.Content = dgPackets.Items.Count;
        }

        private void btnStart_Click(object sender, RoutedEventArgs e)
        {
            t1 = new Thread(() => snifferClass.Start());
            t1.Start();
            t2 = new Thread(() => GetPacketInfo());
            t2.Start();
            btnStart.IsEnabled = false;//Chỉ cho Start một lần
            btnStop.IsEnabled = true;
        }

        private void GetPacketInfo()
        {
            while (true)
            {
                this.Dispatcher.Invoke(() =>
                {
                    dgPackets.ItemsSource = snifferClass.packets;
                });
            }
        }

        private void btnStop_Click(object sender, RoutedEventArgs e)
        {
            t1.Abort();
            t2.Abort();
            //Stop tắt, start mở 
            btnStop.IsEnabled = false;
            btnStart.IsEnabled = true;
        }

        private void btnRestart_Click(object sender, RoutedEventArgs e)
        {
            btnStop_Click(sender, e);
            dgPackets.ItemsSource = null;
            btnStart_Click(sender, e);
        }

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            btnStop_Click(sender, e);
            dgPackets.ItemsSource = null;
        }

        private void btnGoToFirst_Click(object sender, RoutedEventArgs e)
        {
            GoTo(0);
        }

        private void GoTo(int index)
        {
            object item = dgPackets.Items[index];
            dgPackets.SelectedItem = item;
            dgPackets.ScrollIntoView(item);
        }

        private void btnGoToEnd_Click(object sender, RoutedEventArgs e)
        {
            GoTo(dgPackets.Items.Count - 1);
        }

        private void btnAutoScroll_Click(object sender, RoutedEventArgs e)
        {
            if (dgPackets.Items.Count > 0)
            {
                var border = VisualTreeHelper.GetChild(dgPackets, 0) as Decorator;
                if (border != null)
                {
                    var scroll = border.Child as ScrollViewer;
                    if (scroll != null) scroll.ScrollToEnd();
                }
            }
        }

        private void btnGoTo_Click(object sender, RoutedEventArgs e)
        {
            if (int.TryParse(tbxGoTo.Text, out int id))
            {
                if (id >= 1 && id < dgPackets.Items.Count)//Cho phép nhập từ 1 đến số cuối cùng. tuy nhiên lập trình thì cho phép bắt đầu từ 0
                {
                    GoTo(id - 1);
                }
            }
        }

        private void dgPackets_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            PacketInfo packetInfo = (PacketInfo)dgPackets.SelectedItem;
            var buff = new List<PacketBuff>();
            buff.Add(packetInfo.Buffer);
            dgBuff.ItemsSource = null;
            dgBuff.ItemsSource = buff;
        }
    }
}
