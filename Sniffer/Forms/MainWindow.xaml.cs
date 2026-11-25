using Microsoft.Win32;
using Sniffer.Forms;
using SnifferLib;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace Sniffer
{
	public partial class MainWindow : Window
	{
		private readonly SnifferClass snifferClass;
		private readonly ConcurrentQueue<PacketInfo> pendingPackets = new ConcurrentQueue<PacketInfo>();
		private readonly List<PacketInfo> packets = new List<PacketInfo>();
		private readonly DispatcherTimer updateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
		private bool autoScroll;
		private bool goBack;
		private bool fileOperation;

		public MainWindow() : this(SnifferClass.getInstance()) { }

		public MainWindow(SnifferClass snifferClass)
		{
			this.snifferClass = snifferClass ?? throw new ArgumentNullException(nameof(snifferClass));
			InitializeComponent();
			updateTimer.Tick += (_, _) => DrainPackets();
		}

		private void Window_Loaded(object sender, RoutedEventArgs e)
		{
			tbxAdapter.Text = snifferClass.SelectedNameDevice ?? "None";
			tbxComputerName.Text = Environment.MachineName;
			snifferClass.UpdateDataGrid = pendingPackets.Enqueue;
			updateTimer.Start();
			UpdateCaptureButtons();
		}

		private void DrainPackets()
		{
			int count = 0;
			while (count < 500 && pendingPackets.TryDequeue(out var packet))
			{
				packets.Add(packet);
				dgPackets.Items.Add(packet);
				count++;
			}
			if (count == 0)
				return;
			UpdateCounts();
			if (autoScroll && dgPackets.Items.Count > 0)
				dgPackets.ScrollIntoView(dgPackets.Items[dgPackets.Items.Count - 1]);
		}

		private void DrainAllPackets()
		{
			while (!pendingPackets.IsEmpty)
				DrainPackets();
		}

		private void ClearPackets()
		{
			while (pendingPackets.TryDequeue(out _)) { }
			packets.Clear();
			dgPackets.Items.Clear();
			ClearDetails();
			UpdateCounts();
		}

		private void btnStart_Click(object sender, RoutedEventArgs e)
		{
			try
			{
				ClearPackets();
				snifferClass.Start();
				Title = "Sniffer Network Analyzer";
				UpdateCaptureButtons();
			}
			catch (InvalidOperationException exception)
			{
				MessageBox.Show(exception.Message, "Capture error", MessageBoxButton.OK, MessageBoxImage.Error);
				UpdateCaptureButtons();
			}
		}

		private void btnStop_Click(object sender, RoutedEventArgs e) => StopCapture();
		private void btnRestart_Click(object sender, RoutedEventArgs e)
		{
			if (StopCapture())
				btnStart_Click(sender, e);
		}

		private bool StopCapture()
		{
			try
			{
				snifferClass.Stop();
				DrainAllPackets();
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
			btnStart.IsEnabled = !fileOperation && !snifferClass.IsCapturing && snifferClass.SelectedNameDevice is not null;
			btnStop.IsEnabled = !fileOperation && snifferClass.IsCapturing;
			btnRestart.IsEnabled = !fileOperation && snifferClass.SelectedNameDevice is not null;
		}

		private async void btnOpen_Click(object sender, RoutedEventArgs e) => await OpenCaptureAsync();

		public async Task OpenCaptureAsync()
		{
			if (fileOperation)
				return;
			var dialog = new OpenFileDialog { Filter = "Capture files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All files (*.*)|*.*" };
			if (dialog.ShowDialog(this) != true)
				return;
			if (!StopCapture())
				return;
			fileOperation = true;
			UpdateCaptureButtons();
			try
			{
				var loaded = await Task.Run(() =>
				{
					var records = CaptureFile.Read(dialog.FileName);
					var result = new List<PacketInfo>(records.Count);
					DateTimeOffset? first = null;
					foreach (var record in records)
					{
						first ??= record.Timestamp;
						result.Add(PacketParser.Parse(record, result.Count + 1, (record.Timestamp - first.Value).TotalSeconds));
					}
					return result;
				});
				if (!IsLoaded)
					return;
				ClearPackets();
				foreach (var packet in loaded)
				{
					packets.Add(packet);
					dgPackets.Items.Add(packet);
					if (packets.Count % 500 == 0)
						await Dispatcher.Yield(DispatcherPriority.Background);
				}
				UpdateCounts();
				Title = $"Sniffer Network Analyzer - {Path.GetFileName(dialog.FileName)}";
			}
			catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
			{
				MessageBox.Show(exception.Message, "Open capture", MessageBoxButton.OK, MessageBoxImage.Error);
			}
			finally
			{
				fileOperation = false;
				UpdateCaptureButtons();
			}
		}

		private async void btnSave_Click(object sender, RoutedEventArgs e)
		{
			if (fileOperation)
				return;
			var dialog = new SaveFileDialog { Filter = "PCAPNG (*.pcapng)|*.pcapng|PCAP (*.pcap)|*.pcap", DefaultExt = ".pcapng" };
			if (dialog.ShowDialog(this) != true)
				return;
			DrainPackets();
			fileOperation = true;
			UpdateCaptureButtons();
			try
			{
				var source = snifferClass.IsCapturing ? snifferClass.GetCapturedPacketsSnapshot() : packets.ToArray();
				var records = source.Select(packet => packet.Capture ?? throw new InvalidOperationException("Packet data is unavailable.")).ToArray();
				await Task.Run(() => CaptureFile.Write(dialog.FileName, records));
			}
			catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or NotSupportedException)
			{
				MessageBox.Show(exception.Message, "Save capture", MessageBoxButton.OK, MessageBoxImage.Error);
			}
			finally
			{
				fileOperation = false;
				UpdateCaptureButtons();
			}
		}

		private void btnBack_Click(object sender, RoutedEventArgs e)
		{
			if (snifferClass.IsCapturing &&
				MessageBox.Show("Stop capturing and return to the welcome window?", "Capture",
					MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
				return;
			goBack = true;
			Close();
		}

		private void btnClose_Click(object sender, RoutedEventArgs e) => btnBack_Click(sender, e);
		private void btnExit_Click(object sender, RoutedEventArgs e) => Close();

		private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
		{
			if (fileOperation)
			{
				MessageBox.Show("Wait for the file operation to finish.", "Capture", MessageBoxButton.OK, MessageBoxImage.Information);
				e.Cancel = true;
				goBack = false;
				return;
			}
			if (!goBack)
			{
				var quit = new QuitWindow();
				quit.ShowDialog();
				if (quit.Mode == QuitMode.Cancel)
				{
					e.Cancel = true;
					return;
				}
			}
			if (!StopCapture())
			{
				e.Cancel = true;
				goBack = false;
				return;
			}
			updateTimer.Stop();
			snifferClass.UpdateDataGrid = null;
			if (!goBack)
				Application.Current.Shutdown();
		}

		private void btnAbout_Click(object sender, RoutedEventArgs e) =>
			MessageBox.Show("Sniffer Network Analyzer", "About", MessageBoxButton.OK, MessageBoxImage.Information);
		private void btnDoc_Click(object sender, RoutedEventArgs e) =>
			MessageBox.Show("https://github.com/quocthang0507/Sniffer", "Documentation");

		private void GoTo(int index)
		{
			if (index < 0 || index >= dgPackets.Items.Count)
				return;
			dgPackets.SelectedIndex = index;
			dgPackets.ScrollIntoView(dgPackets.Items[index]);
		}
		private void btnGoToFirst_Click(object sender, RoutedEventArgs e) => GoTo(0);
		private void btnGoToEnd_Click(object sender, RoutedEventArgs e) => GoTo(dgPackets.Items.Count - 1);
		private void btnGoTo_Click(object sender, RoutedEventArgs e)
		{
			if (int.TryParse(tbxGoTo.Text, out int index))
				GoTo(index - 1);
		}
		private void btnPreviousPacket_Click(object sender, RoutedEventArgs e) => GoTo(dgPackets.SelectedIndex - 1);
		private void btnNextPacket_Click(object sender, RoutedEventArgs e) => GoTo(dgPackets.SelectedIndex + 1);
		private void btnAutoScroll_Click(object sender, RoutedEventArgs e) => autoScroll = !autoScroll;

		private void HexBytes_SelectionChanged(object sender, RoutedEventArgs e)
		{
			if (dgPackets?.SelectedItem is PacketInfo packet)
				tbxDecode.Text = packet.Buffer.Content;
		}

		private void HexBytes_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			int characterIndex = tbxBuffer.GetCharacterIndexFromPoint(e.GetPosition(tbxBuffer), false);
			if (characterIndex < 0)
				return;

			int lineIndex = tbxBuffer.GetLineIndexFromCharacterIndex(characterIndex);
			int lineStart = tbxBuffer.GetCharacterIndexFromLineIndex(lineIndex);
			string line = tbxBuffer.GetLineText(lineIndex);
			int offsetEnd = line.IndexOf("  ", StringComparison.Ordinal);
			int byteStart = offsetEnd + 2;
			int relativeIndex = characterIndex - lineStart - byteStart;
			if (offsetEnd < 0 || relativeIndex < 0 || relativeIndex % 4 >= 2)
				return;

			int byteColumn = relativeIndex / 4;
			if (byteColumn >= 16 || dgPackets.SelectedItem is not PacketInfo packet)
				return;
			string ascii = packet.Buffer.Content;
			int asciiIndex = lineIndex * 17 + byteColumn;
			if (asciiIndex >= ascii.Length || ascii[asciiIndex] == '\n')
				return;

			tbxBuffer.Focus();
			tbxBuffer.Select(lineStart + byteStart + byteColumn * 4, 2);
			tbxDecode.Inlines.Clear();
			tbxDecode.Inlines.Add(new Run(ascii[..asciiIndex]));
			tbxDecode.Inlines.Add(new Run(ascii.Substring(asciiIndex, 1)) { Background = Brushes.Orange });
			tbxDecode.Inlines.Add(new Run(ascii[(asciiIndex + 1)..]));
			e.Handled = true;
		}

		private void dgPackets_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			ClearDetails();
			if (dgPackets.SelectedItem is not PacketInfo packet)
				return;
			tbxBuffer.Text = packet.Buffer.Buffer;
			tbxDecode.Text = packet.Buffer.Content;
			AddLayer($"Frame {packet.ID}: {packet.Length} bytes", packet.Capture is null ? null :
				$"Timestamp: {packet.Capture.Timestamp:O}\nCaptured length: {packet.Capture.Data.Length} bytes\nOriginal length: {packet.Capture.OriginalLength} bytes");
			AddLayer("Ethernet II", packet.Layers.EthernetInfo);
			AddLayer(packet.Protocol == "ARP" ? "Address Resolution Protocol" : "Internet Protocol", packet.Layers.IPInfo);
			AddLayer("Transmission Control Protocol", packet.Layers.TCPInfo);
			AddLayer("User Datagram Protocol", packet.Layers.UDPInfo);
			AddLayer("Internet Control Message Protocol", packet.Layers.ICMPInfo);
			AddLayer("Domain Name System", packet.Layers.DNSInfo);
			AddLayer("Hypertext Transfer Protocol", packet.Layers.HTTPInfo);
		}

		private void ClearDetails()
		{
			tvDetails.Items.Clear();
			tbxBuffer.Text = string.Empty;
			tbxDecode.Text = string.Empty;
		}

		private void AddLayer(string title, string? details)
		{
			if (details is null)
				return;
			var item = new TreeViewItem { Header = title };
			foreach (string line in details.Split('\n'))
				item.Items.Add(new TreeViewItem { Header = line });
			tvDetails.Items.Add(item);
		}

		private void UpdateCounts()
		{
			tbxTotalPackets.Text = packets.Count.ToString();
			tbxTotalDisPackets.Text = dgPackets.Items.Count.ToString();
		}

		private void tbxFindWhat_TextChanged(object sender, TextChangedEventArgs e)
		{
			if (dgPackets is null || filterError is null)
				return;
			try
			{
				var filter = DisplayFilter.Parse(tbxFindWhat.Text);
				dgPackets.Items.Filter = item => item is PacketInfo packet && filter(packet);
				tbxFindWhat.Background = Brushes.Honeydew;
				filterError.Text = string.Empty;
				UpdateCounts();
			}
			catch (FormatException exception)
			{
				tbxFindWhat.Background = Brushes.MistyRose;
				filterError.Text = exception.Message;
			}
		}
	}
}
