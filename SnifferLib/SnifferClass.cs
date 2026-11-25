using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;

namespace SnifferLib
{
	/// <summary>
	/// Tầng Business: Xử lý các thao tác Sniffer
	/// </summary>
	public class SnifferClass
	{
		private List<NetworkInterface> devices = new List<NetworkInterface>();
		private readonly IList<ILiveDevice> captureDevices;
		private ILiveDevice? selectedCaptureDevice;
		private ILiveDevice? activeCaptureDevice;
		private Stopwatch stopwatch = new Stopwatch();
		private readonly Exception? captureDeviceInitializationError;
		private static SnifferClass? instance;

		/// <summary>
		/// Danh sách các gói tin đã bắt được
		/// </summary>
		public BindingList<PacketInfo> ListCapturedPackets { get; private set; } = new BindingList<PacketInfo>();

		/// <summary>
		/// Hàm ủy quyền thêm gói tin vào data grid
		/// </summary>
		/// <param name="packet"></param>
		public delegate void AddItemToDataGrid(PacketInfo packet);

		public AddItemToDataGrid? UpdateDataGrid;

		public List<string> ListNameDevices { get { return GetInterfaces(); } }

		public string? SelectedNameDevice { get; private set; }

		public bool IsCapturing { get { return activeCaptureDevice is not null; } }

		private SnifferClass()
		{
			try
			{
				captureDevices = CaptureDeviceList.Instance.ToList();
			}
			catch (Exception exception) when (
				exception is PcapException or
				DllNotFoundException or
				PlatformNotSupportedException)
			{
				captureDevices = new List<ILiveDevice>();
				captureDeviceInitializationError = exception;
			}
		}

		/// <summary>
		/// Singleton Pattern
		/// </summary>
		/// <returns></returns>
		public static SnifferClass getInstance()
		{
			instance ??= new SnifferClass();
			return instance;
		}

		/// <summary>
		/// Lấy danh sách card mạng trong máy tính
		/// </summary>
		/// <returns></returns>
		private List<string> GetInterfaces()
		{
			devices = NetworkInterface.GetAllNetworkInterfaces().ToList();
			return devices
				.Select(networkInterface => $"{networkInterface.Description} - {networkInterface.Name} - {networkInterface.Id}")
				.ToList();
		}

		/// <summary>
		/// Lựa chọn card mạng theo số thứ tự
		/// </summary>
		/// <param name="index"></param>
		public void SetSelectedInterface(int index)
		{
			if (index < 0 || index >= devices.Count)
			{
				throw new ArgumentOutOfRangeException(nameof(index), "Select a valid network interface.");
			}

			NetworkInterface networkInterface = devices[index];
			string id = networkInterface.Id.Trim('{', '}');
			selectedCaptureDevice = captureDevices.FirstOrDefault(device =>
				device.Name.Contains(id, StringComparison.OrdinalIgnoreCase));

			if (selectedCaptureDevice is null)
			{
				throw new InvalidOperationException(
					"The selected interface is not available for capture. Install Npcap and select a supported adapter.",
					captureDeviceInitializationError);
			}

			SelectedNameDevice = networkInterface.Description;
		}

		/// <summary>
		/// Bắt đầu quá trình bắt gói tin
		/// </summary>
		public void Start()
		{
			if (selectedCaptureDevice is null)
			{
				throw new InvalidOperationException("Select a capture-capable network interface before starting.");
			}

			if (activeCaptureDevice is not null)
			{
				throw new InvalidOperationException("Packet capture is already running.");
			}

			ListCapturedPackets = new BindingList<PacketInfo>();
			stopwatch = Stopwatch.StartNew();

			ILiveDevice device = selectedCaptureDevice;
			bool opened = false;
			device.OnPacketArrival += PacketHandler;
			try
			{
				device.Open(DeviceModes.Promiscuous, 1000);
				opened = true;
				device.StartCapture();
				activeCaptureDevice = device;
			}
			catch (Exception exception) when (
				exception is PcapException or
				DllNotFoundException or
				PlatformNotSupportedException or
				InvalidOperationException)
			{
				device.OnPacketArrival -= PacketHandler;
				Exception cause = exception;
				if (opened)
				{
					try
					{
						device.Close();
					}
					catch (Exception closeException) when (
						closeException is PcapException or
						InvalidOperationException)
					{
						cause = new AggregateException(exception, closeException);
					}
				}
				stopwatch.Stop();
				throw new InvalidOperationException(
					"Could not start packet capture. Verify that Npcap is installed and the selected adapter supports capture.",
					cause);
			}
		}

		public void Stop()
		{
			ILiveDevice? device = activeCaptureDevice;
			if (device is null)
			{
				return;
			}

			device.OnPacketArrival -= PacketHandler;
			activeCaptureDevice = null;
			Exception? failure = null;
			try
			{
				if (device.Started)
					device.StopCapture();
			}
			catch (Exception exception) when (
				exception is PcapException or
				InvalidOperationException)
			{
				failure = exception;
			}

			try
			{
				device.Close();
			}
			catch (Exception exception) when (
				exception is PcapException or
				InvalidOperationException)
			{
				failure = failure is null ? exception : new AggregateException(failure, exception);
			}
			finally
			{
				stopwatch.Stop();
			}

			if (failure is not null)
				throw new InvalidOperationException("Could not stop packet capture cleanly.", failure);
		}

		private void PacketHandler(object sender, PacketCapture e)
		{
			RawCapture capture = e.GetPacket();
			int id = ListCapturedPackets.Count + 1;
			double elapsedSeconds = stopwatch.Elapsed.TotalSeconds;
			PacketInfo packet = PacketParser.Parse(capture.Data, capture.LinkLayerType, id, elapsedSeconds);
			ListCapturedPackets.Add(packet);
			UpdateDataGrid?.Invoke(packet);
		}
	}
}
