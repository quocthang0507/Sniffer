using Sniffer.Forms;
using SnifferLib;
using System;
using System.Windows;
using System.Windows.Controls;

namespace Sniffer
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		private readonly SnifferClass snifferClass;
		private bool autoScroll = false;
		private bool goBack = false;

		public MainWindow()
			: this(SnifferClass.getInstance())
		{
		}

		public MainWindow(SnifferClass snifferClass)
		{
			this.snifferClass = snifferClass ?? throw new ArgumentNullException(nameof(snifferClass));
			InitializeComponent();
		}

		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			goBack = false;
			// Lấy thông tin interface đã chọn từ WelcomeWindow
			GetSelectedInterface();
			// Lấy tên của máy tính
			GetComputerName();
			// Ủy quyền cập nhật DataGrid cho một lớp bên ngoài
			snifferClass.UpdateDataGrid = new SnifferClass.AddItemToDataGrid(UpdateDataGrid);
			HideLayersWhenNotClicked();
		}

		/// <summary>
		/// Cập nhật DataGrid trên UI thread khi nhận được packet từ capture callback.
		/// </summary>
		/// <param name="packet"></param>
		private void UpdateDataGrid(PacketInfo packet)
		{
			Dispatcher.BeginInvoke(() =>
			{
				if (!IsLoaded)
					return;

				dgPackets.Items.Add(packet);
				UpdateDisplayedPackets();
				UpdateTotalPackets();
			});
		}

		private void btnBack_Click(object sender, RoutedEventArgs e)
		{
			if (snifferClass.IsCapturing)
			{
				var msgBox = MessageBox.Show("The current task is working! " +
					"Do you want to stop capturing packets and go back to the welcome window?", "Warning",
					MessageBoxButton.YesNo, MessageBoxImage.Warning);
				if (msgBox == MessageBoxResult.Yes)
					StopCapture();
				else
					return;
			}
			goBack = true;
			this.Close();
		}

		private void btnExit_Click(object sender, RoutedEventArgs e)
		{
			if (!goBack)
				return;
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
			MessageBox.Show("https://github.com/dotpcap/SharpPcap/wiki",
				"Tài liệu tham khảo!", MessageBoxButton.OK, MessageBoxImage.Information);
		}

		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			if (!goBack)
			{
				QuitWindow quitWindow = new QuitWindow();
				quitWindow.ShowDialog();
				if (quitWindow.Mode == QuitMode.Cancel)
				{
					e.Cancel = true;
					return;
				}
			}

			StopCapture();
			snifferClass.UpdateDataGrid = null;
			if (!goBack)
				Application.Current.Shutdown();
		}

		private void GetSelectedInterface()
		{
			tbxAdapter.Content = snifferClass.SelectedNameDevice;
		}

		private void GetComputerName()
		{
			tbxComputerName.Content = Environment.MachineName;
		}

		private void btnStart_Click(object sender, RoutedEventArgs e)
		{
			dgPackets.Items.Clear();
			try
			{
				snifferClass.Start();
				btnStart.IsEnabled = false;
				btnStop.IsEnabled = true;
				UpdateTotalPackets();
				UpdateDisplayedPackets();
			}
			catch (InvalidOperationException exception)
			{
				MessageBox.Show(exception.Message, "Capture error", MessageBoxButton.OK, MessageBoxImage.Error);
				UpdateCaptureButtons();
			}
		}

		private void btnStop_Click(object sender, RoutedEventArgs e)
		{
			StopCapture();
		}

		private void btnRestart_Click(object sender, RoutedEventArgs e)
		{
			if (!StopCapture())
				return;
			btnStart_Click(sender, e);
		}

		private void btnClose_Click(object sender, RoutedEventArgs e)
		{
			StopCapture();
			goBack = true;
			Close();
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
				if (id >= 1 && id <= dgPackets.Items.Count)
				{
					GoTo(id - 1); // Chuyển cách đếm số từ 1 về cách đếm số từ 0 (cách máy tính lưu trữ)
				}
			}
		}

		/// <summary>
		/// Đi đến một packet có thứ tự index trong DataGrid
		/// </summary>
		/// <param name="index"></param>
		private void GoTo(int index)
		{
			if (index < 0 || index >= dgPackets.Items.Count)
				return;

			object item = dgPackets.Items[index];
			dgPackets.SelectedItem = item;
			dgPackets.ScrollIntoView(item);
		}

		private void btnAutoScroll_Click(object sender, RoutedEventArgs e)
		{
			// Cho phép bật/tắt tự động lăn xuống dưới cùng
			autoScroll = !autoScroll;
			if (dgPackets.Items.Count > 0)
				dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
		}

		private void dgPackets_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			// Lấy thông tin của gói tin đang được chọn trong DataGrid hiển thị chi tiết buffer
			if (dgPackets.SelectedItem is PacketInfo packetInfo)
			{
				tbxBuffer.Text = packetInfo.Buffer.Buffer;
				tbxDecode.Text = packetInfo.Buffer.Content;
				UpdateLayers(packetInfo.Layers);
			}
		}

		private void HideLayersWhenNotClicked()
		{
			isIcmp.Visibility = Visibility.Collapsed;
			isHttp.Visibility = Visibility.Collapsed;
			isTcp.Visibility = Visibility.Collapsed;
			isUdp.Visibility = Visibility.Collapsed;
		}

		private void UpdateLayers(PacketLayer layers)
		{
			HideLayersWhenNotClicked();
			if (layers != null)
			{
				if (layers.HTTPInfo != null)
				{
					isHttp.Visibility = Visibility.Visible;
					tbxHttp.Text = layers.HTTPInfo;
				}
				if (layers.TCPInfo != null)
				{
					isTcp.Visibility = Visibility.Visible;
					tbxTcp.Text = layers.TCPInfo;
				}
				if (layers.UDPInfo != null)
				{
					isUdp.Visibility = Visibility.Visible;
					tbxUdp.Text = layers.UDPInfo;
				}
				if (layers.ICMPInfo != null)
				{
					isIcmp.Visibility = Visibility.Visible;
					tbxIcmp.Text = layers.ICMPInfo;
				}
				tbxEthernet.Text = layers.EthernetInfo ?? string.Empty;
				tbxIp.Text = layers.IPInfo ?? string.Empty;
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
			int nextIndex = dgPackets.SelectedIndex + 1;
			if (nextIndex < dgPackets.Items.Count)
				GoTo(nextIndex);
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
		private void UpdateTotalPackets()
		{
			tbxTotalPackets.Content = snifferClass.ListCapturedPackets.Count;
		}

		private void tbxFindWhat_TextChanged(object sender, TextChangedEventArgs e)
		{
			dgPackets.Items.Filter = item => // Tùy chỉnh phương thức lọc nội dung cho DataGrid 
			{
				string filter = tbxFindWhat.Text;
				if (filter.Length > 0)
				{
					return item is PacketInfo packet &&
						packet.Protocol.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
				}
				return true;
			};
			UpdateDisplayedPackets();
		}

		private bool StopCapture()
		{
			try
			{
				snifferClass.Stop();
				return true;
			}
			catch (InvalidOperationException exception)
			{
				MessageBox.Show(exception.Message, "Capture error", MessageBoxButton.OK, MessageBoxImage.Error);
				return false;
			}
			finally
			{
				UpdateCaptureButtons();
			}
		}

		private void UpdateCaptureButtons()
		{
			btnStart.IsEnabled = !snifferClass.IsCapturing;
			btnStop.IsEnabled = snifferClass.IsCapturing;
		}
	}
}
