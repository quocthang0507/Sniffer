using Sniffer.Forms;
using SnifferLib;
using System;
using System.Threading;
using System.Windows;
using System.Windows.Controls;

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
		}

		public MainWindow(SnifferClass snifferClass)
		{
			this.snifferClass = snifferClass;
			InitializeComponent();
			// Lấy thông tin interface đã chọn từ WelcomeWindow
			GetSelectedInterface();
			// Lấy tên của máy tính
			GetComputerName();
			// Ủy quyền cập nhật DataGrid cho một lớp bên ngoài
			snifferClass.UpdateDataGrid = new SnifferClass.AddItemToDataGrid(UpdateDataGrid);
		}

		/// <summary>
		/// Cập nhật datagrid mỗi khi bắt được một gói tin, hàm này được gọi bởi một lớp bên ngoài nên phải dùng Dispatcher.Invoke
		/// </summary>
		/// <param name="packet"></param>
		private void UpdateDataGrid(PacketInfo packet)
		{
			Dispatcher.Invoke(() => dgPackets.Items.Add(packet)); // bắt được gói tin thì cập nhật vào list
			UpdateOthers();
		}

		/// <summary>
		/// Cập nhật thông tin lên các control, đồng thời làm cho thao tác trên form mượt hơn nhờ vào thread
		/// </summary>
		private void UpdateOthers()
		{
			new Thread(() =>
			{
				Dispatcher.Invoke(() =>
				{
					dgPackets.Items.Filter = item => // Tùy chỉnh phương thức lọc nội dung cho DataGrid 
					{
						string filter = tbxFindWhat.Text;
						if (filter != "") // Mặc định là hiển thị tất cả
						{
							return (item as PacketInfo).Protocol.Contains(filter); // Chỉ xuất những cái thỏa điều kiện
						}
						return true; // Còn không thì xuất tất cả lên DataGrid
					};
				});
				Dispatcher.Invoke(() => UpdateDisplayedPackets()); // Cập nhật số lượng packet hiển thị trên DataGrid
				Dispatcher.Invoke(() => UpadateTotalPackets()); // Cập nhật số lượng packet đã bắt được
			}).Start();
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
			MessageBox.Show("Thành viên trong nhóm: \r\n " +
				"1. La Quốc Thắng 1610207 (Thiết kế giao diện) \r\n " +
				"2. Nguyễn Thị Bích Ngọc 1610171 (Thiết kế chức năng) \r\n " +
				"3. Nguyễn Thị Linh 1610156 (Thiết kế chức năng)", "Giới thiệu!", MessageBoxButton.OK, MessageBoxImage.Information);
		}

		private void btnDoc_Click(object sender, RoutedEventArgs e)
		{
			MessageBox.Show("https://github.com/PcapDotNet/Pcap.Net/wiki/Pcap.Net-Tutorial", 
				"Tài liệu tham khảo!", MessageBoxButton.OK, MessageBoxImage.Information);
		}

		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			QuitWindow quitWindow = new QuitWindow();
			quitWindow.ShowDialog();
			if (quitWindow.Mode == QuitMode.Cancel)
				e.Cancel = true;
			else
			{
				if (thread != null)
					thread.Abort();
				Application.Current.Shutdown();
			}
		}

		private void GetSelectedInterface()
		{
			tbxAdapter.Content = snifferClass.GetNameSelectedInterface();
		}

		private void GetComputerName()
		{
			tbxComputerName.Content = Environment.MachineName.ToString();
		}

		private void btnStart_Click(object sender, RoutedEventArgs e)
		{
			dgPackets.Items.Clear(); // Xóa dữ liệu trong DataGrid
			// Tạo một thread mới thực hiện công việc là bắt gói tin
			thread = new Thread(() => snifferClass.Start());
			thread.Start();
			btnStart.IsEnabled = false; // Chỉ cho Start một lần
			btnStop.IsEnabled = true; // Nút Stop sáng lên ngay sau khi Start
		}

		private void btnStop_Click(object sender, RoutedEventArgs e)
		{
			// Stop thread
			thread.Abort();
			btnStop.IsEnabled = false;
			btnStart.IsEnabled = true;
		}

		private void btnRestart_Click(object sender, RoutedEventArgs e)
		{
			// Stop công việc và bắt đầu lại
			btnStop_Click(sender, e);
			btnStart_Click(sender, e);
		}

		private void btnClose_Click(object sender, RoutedEventArgs e)
		{
			// Stop công việc và xóa sạch DataGrid
			btnStop_Click(sender, e);
			dgPackets.Items.Clear();
		}

		private void btnGoToFirst_Click(object sender, RoutedEventArgs e)
		{
			GoTo(0);
		}

		private void btnGoToEnd_Click(object sender, RoutedEventArgs e)
		{
			// Đến dòng cuối cùng trong DataGrid
			GoTo(dgPackets.Items.Count - 1);
		}

		private void btnGoTo_Click(object sender, RoutedEventArgs e)
		{
			if (int.TryParse(tbxGoTo.Text, out int id))
			{
				if (id >= 1 && id < dgPackets.Items.Count) // Chỉ cho phép nhập trong phạm vi từ 1 đến hết danh sách
				{
					GoTo(id - 1); // Chuyển cách đếm số từ 1 về cách đếm số từ 0 (cách máy tính lưu trữ)
				}
			}
		}

		/// <summary>
		/// Đi đến một packet có thứ tự index trong DataGrid
		/// </summary>
		/// <param name="index"></param>`
		private void GoTo(int index)
		{
			if (index != -1)
			{
				object item = dgPackets.Items[index];
				dgPackets.SelectedItem = item;
				dgPackets.ScrollIntoView(item);
			}
		}

		private void btnAutoScroll_Click(object sender, RoutedEventArgs e)
		{
			// Cho phép bật/tắt tự động lăn xuống dưới cùng
			autoScroll = !autoScroll;
			dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
		}

		private void dgPackets_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			// Lấy thông tin của gói tin đang được chọn trong DataGrid hiển thị chi tiết buffer
			PacketInfo packetInfo = (PacketInfo)dgPackets.SelectedItem;
			if (packetInfo != null)
			{
				var buff = packetInfo.Buffer;
				tbxBuffer.Text = buff.Buffer;
				tbxDecode.Text = buff.Content;
			}
		}

		/// <summary>
		/// https://stackoverflow.com/a/33045967
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void dgPackets_ScrollChanged(object sender, ScrollChangedEventArgs e)
		{
			// Nếu đang bật AutoScroll
			if (autoScroll)
			{
				// Nếu trong DataGrid, các dòng nằm đủ trong một view thì bỏ qua
				if (e.ExtentHeight < e.ViewportHeight)
					return;
				// Nếu không có gì trong DataGrid thì bỏ qua
				if (dgPackets.Items.Count <= 0)
					return;
				// Nếu trong DataGrid không thay đổi thì bỏ qua
				if (e.ExtentHeightChange == 0.0 && e.ViewportHeightChange == 0.0)
					return;
				// Lăn đến dòng cuối cùng
				dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
			}
		}

		private void btnPreviousPacket_Click(object sender, RoutedEventArgs e)
		{
			// Đi đến packet nằm trước nó
			if (dgPackets.SelectedIndex > 0)
			{
				int index = dgPackets.SelectedIndex;
				GoTo(index - 1);
			}
		}

		private void btnNextPacket_Click(object sender, RoutedEventArgs e)
		{
			// Đi đến packet nằm sau nó
			if (dgPackets.SelectedIndex < dgPackets.Items.Count)
			{
				int index = dgPackets.SelectedIndex;
				GoTo(index + 1);
			}
		}

		/// <summary>
		/// Cập nhập hiển thị số lượng packet hiển thị trên DataGrid
		/// </summary>
		private void UpdateDisplayedPackets()
		{
			tbxTotalDisPackets.Content = dgPackets.Items.Count;
		}

		/// <summary>
		/// Cập nhập số lượng packet đã bắt được
		/// </summary>
		private void UpadateTotalPackets()
		{
			tbxTotalPackets.Content = snifferClass.CapturedPackets.Count;
		}
	}
}
