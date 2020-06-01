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
        private Thread thread;
        private bool autoScroll = false;

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
            snifferClass.UpdateDataGrid = new SnifferClass.AddItemToDataGrid(UpdateDataGrid);
        }

        /// <summary>
        /// 
        /// Cập nhật datagrid mỗi khi snifferclass bắt được một gói tin
        /// </summary>
        /// <param name="packet"></param>
        private void UpdateDataGrid(PacketInfo packet)
        {
            Dispatcher.Invoke(() => dgPackets.Items.Add(packet));//bắt được gói tin thì bắt cập nhật vào list
            Dispatcher.Invoke(() =>
            {
                //gọi là snifferclass, dưới là một hàm cho snifferclass sử dụng,sniffercl ở bên ngoài form nên phải dùng dispatcher mới truy cập được control trong form
                dgPackets.Items.Filter = item => //lọc phải đưa 1 hàm, tìm theo kiểu bao trùm, 
                {
                    string filter = tbxFindWhat.Text;
                    if (filter != "")//mặc dịnh là hiển thị tất cả
                    {
                        return (item as PacketInfo).Protocol.Contains(filter);//chỉ cần chứa 1 kí tự
                    }
                    return true;//đúng thì hiện lên màn hình chỉ thực hiện khi nào có chữ bên trong nó
                };
            });
            Dispatcher.Invoke(() => UpdateDisplayedPackets());
            Dispatcher.Invoke(() => UpadateTotalPackets());
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
                thread.Abort();
                Application.Current.Shutdown();
            }
            else
            {
                thread.Abort();
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

        private void btnStart_Click(object sender, RoutedEventArgs e)//snifferclass nằm gọn trong 1 threat khác form nên sẽ dùng dispatcher.info 
        {
            thread = new Thread(() => snifferClass.Start());
            thread.Start();
            btnStart.IsEnabled = false;//Chỉ cho Start một lần
            btnStop.IsEnabled = true;
        }

        private void btnStop_Click(object sender, RoutedEventArgs e)
        {
            thread.Abort();
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
            if (index != -1)
            {
                object item = dgPackets.Items[index];
                dgPackets.SelectedItem = item;
                dgPackets.ScrollIntoView(item);
            }
        }

        private void btnGoToEnd_Click(object sender, RoutedEventArgs e)
        {
            GoTo(dgPackets.Items.Count - 1);
        }

        private void btnAutoScroll_Click(object sender, RoutedEventArgs e)
        {
            autoScroll = !autoScroll;
            dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
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

        private void dgPackets_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (autoScroll)
            {
                // If the entire contents fit on the screen, ignore this event
                if (e.ExtentHeight < e.ViewportHeight)
                    return;

                // If no items are available to display, ignore this event
                if (dgPackets.Items.Count <= 0)
                    return;

                // If the ExtentHeight and ViewportHeight haven't changed, ignore this event
                if (e.ExtentHeightChange == 0.0 && e.ViewportHeightChange == 0.0)
                    return;

                // If we were close to the bottom when a new item appeared,
                // scroll the new item into view.  We pick a threshold of 5
                // items since issues were seen when resizing the window with
                // smaller threshold values.
                var oldExtentHeight = e.ExtentHeight - e.ExtentHeightChange;
                var oldVerticalOffset = e.VerticalOffset - e.VerticalChange;
                var oldViewportHeight = e.ViewportHeight - e.ViewportHeightChange;
                if (oldVerticalOffset + oldViewportHeight + 5 >= oldExtentHeight)
                    dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
            }
        }

        private void btnFind_Click(object sender, RoutedEventArgs e)
        {

        }

        private void btnPreviousPacket_Click(object sender, RoutedEventArgs e)
        {
            if (dgPackets.SelectedIndex > 0)
            {
                int index = dgPackets.SelectedIndex;
                GoTo(index - 1);// sử dụng hàm Goto khi click mũi tên trái thì lùi 1
            }
        }

        private void btnNextPacket_Click(object sender, RoutedEventArgs e)
        {
            if (dgPackets.SelectedIndex < dgPackets.Items.Count)
            {
                int index = dgPackets.SelectedIndex;
                GoTo(index + 1);// sử dụng hàm Goto khi click mũi tên trái thì tiến 1
            }
        }
        
       /// <summary>
       /// Cập nhập hiển thị số lượng packet hiển thị trên màn hình.
       /// </summary>
        private void UpdateDisplayedPackets()
        {
            tbxTotalDisPackets.Content = dgPackets.Items.Count;
        }

        /// <summary>
        /// Cập nhập số lượng packets trong danh sách ban đầu.
        /// </summary>
        private void UpadateTotalPackets()
        {
            tbxTotalPackets.Content = snifferClass.packets.Count;
        }
    }
}
