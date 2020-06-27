using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;

namespace SnifferLib
{
	/// <summary>
	/// Tầng Business: Xử lý các thao tác Sniffer
	/// </summary>
	public class SnifferClass
	{
		/// <summary>
		/// Danh sách interface có trong máy tính
		/// </summary>
		private List<NetworkInterface> devices;
		/// <summary>
		/// Danh sách interface mà WinPcap có thể bắt gói tin được
		/// </summary>
		private IList<LivePacketDevice> winpcapDevices;
		/// <summary>
		/// Interface được chọn
		/// </summary>
		private NetworkInterface selectedDevice;
		/// <summary>
		/// Interface tương ứng trong WinPcap
		/// </summary>
		private PacketDevice selectedWinpcapDevice;
		/// <summary>
		/// Đo thời gian của từng gói tin
		/// </summary>
		private Stopwatch stopwatch;
		/// <summary>
		/// Thể hiện tĩnh của lớp (dùng Singleton)
		/// </summary>
		private static SnifferClass instance;

		/// <summary>
		/// Danh sách các gói tin đã bắt được
		/// </summary>
		public BindingList<PacketInfo> ListCapturedPackets { get; set; }

		/// <summary>
		/// Hàm ủy quyền thêm gói tin vào data grid
		/// </summary>
		/// <param name="packet"></param>
		public delegate void AddItemToDataGrid(PacketInfo packet);

		public AddItemToDataGrid UpdateDataGrid;

		public List<string> ListNameDevices { get { return GetInterfaces(); } }

		public string SelectedNameDevice { get; set; }

		private SnifferClass()
		{
			winpcapDevices = LivePacketDevice.AllLocalMachine;
		}

		/// <summary>
		/// Singleton Pattern
		/// </summary>
		/// <returns></returns>
		public static SnifferClass getInstance()
		{
			if (instance == null)
			{
				instance = new SnifferClass();
			}
			return instance;
		}

		/// <summary>
		/// Lấy danh sách card mạng trong máy tính
		/// </summary>
		/// <returns></returns>
		private List<string> GetInterfaces()
		{
			List<string> values = new List<String>();
			devices = NetworkInterface.GetAllNetworkInterfaces().ToList();
			foreach (NetworkInterface @interface in devices)
			{
				values.Add($"{@interface.Description} - {@interface.Name} - {@interface.Id}");
			}
			return values;
		}

		/// <summary>
		/// Lựa chọn card mạng theo số thứ tự
		/// </summary>
		/// <param name="index"></param>
		public void SetSelectedInterface(int index)
		{
			selectedDevice = devices[index];
			SelectedNameDevice = selectedDevice.Description;
			string id = selectedDevice.Id.Replace("{", "").Replace("}", "");
			try
			{
				selectedWinpcapDevice = winpcapDevices.First(d => d.Name.Contains(id));
			}
			catch (Exception)
			{
				throw new Exception("The interface that you have selected does not support to capture packets, please try other again");
			}
		}


		/// <summary>
		/// Thêm sự kiện khi một gói tin đã thêm vào danh sách
		/// </summary>
		private void AddListChangedEvent()
		{
			ListCapturedPackets.ListChanged += (sender, e) =>
			  {
				  UpdateDataGrid(ListCapturedPackets[ListCapturedPackets.Count - 1]);
			  };
		}

		/// <summary>
		/// Bắt đầu quá trình bắt gói tin
		/// </summary>
		public void Start()
		{
			if (winpcapDevices.Count == 0)
			{
				throw new AggregateException("No interfaces found! Make sure WinPcap is installed.");
			}
			ListCapturedPackets = new BindingList<PacketInfo>();
			AddListChangedEvent();
			stopwatch = new Stopwatch();
			using (PacketCommunicator communicator =
				selectedWinpcapDevice.Open(65536,                           // 2^16byte, 64kb, max size của gói tin
									PacketDeviceOpenAttributes.Promiscuous, // Chế độ bắt tất cả gói tin đang truyền trên mạng
									1000))                                  // read timeout
			{
				try
				{
					stopwatch.Start();
					communicator.ReceivePackets(0, PacketHandler);
				}
				catch (Exception)
				{
				}
			}
		}

		/// <summary>
		/// Phân tích gói tin và cho vào danh sách gói tin đã bắt được
		/// </summary>
		/// <param name="packet">Gói tin đang được xử lý</param>
		private void PacketHandler(Packet packet)
		{
			///////////////////Lấy thông tin cơ bản///////////////////////
			PacketInfo info = new PacketInfo();
			info.ID = ListCapturedPackets.Count + 1; // ban đầu là 0 id =1
			info.Time = stopwatch.Elapsed.TotalSeconds;
			IpV4Datagram ip = packet.Ethernet.IpV4;
			info.Source = ip.Source.ToString();
			info.Destination = ip.Destination.ToString();
			info.Protocol = packet.Ethernet.IpV4.Protocol.ToString();
			info.Length = packet.Length;
			string hex = packet.BytesSequenceToHexadecimalString();
			info.Buffer = new PacketBuff(ProcessString(hex), HextoString(hex));
			///////////////////Lấy thông tin ở các tầng trong TCP/IP///////////////////////
			info.Layers = new PacketLayer();
			GetEthernetType(packet, info);
			///////////////////Thêm vào danh sách///////////////////////
			ListCapturedPackets.Add(info);
		}

		private string HextoString(string hex)
		{
			byte[] raw = new byte[hex.Length / 2];
			for (int i = 0; i < raw.Length; i++)
			{
				raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}
			return Encoding.UTF8.GetString(raw);
		}

		private string ProcessString(string hex)
		{
			string formatted = "";
			int splitter = 0;
			for (var i = 0; i < hex.Length; i += 2)
			{
				formatted += hex.Substring(i, 2) + "  ";
				splitter++;
				if (splitter % 16 == 0)
					formatted += "\n";
			}
			return formatted;
		}

		private void GetEthernetType(Packet packet, PacketInfo info)
		{
			switch (packet.Ethernet.EtherType)
			{
				case PcapDotNet.Packets.Ethernet.EthernetType.None:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.IpV4:
					var ip = packet.Ethernet.IpV4;
					info.Layers.IPInfo = $"Internet Protocol Version 4\nSource: {ip.Source}\nDestination: {ip.Destination}" +
						$"\nHeader Length: {ip.HeaderLength}" +
						$"\nTotal Length: {ip.TotalLength}" +
						$"\nTime to live: {ip.Ttl}";
					GetIpProtocol(packet, info);
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.Arp:
					info.Protocol = "ARP";
					var arp = packet.Ethernet.Arp;
					var senderIP = arp.SenderProtocolIpV4Address;
					var targetIP = arp.TargetProtocolIpV4Address;
					info.Source = packet.Ethernet.Source.ToString();
					info.Destination = packet.Ethernet.Destination.ToString();
					if (info.Destination == "FF:FF:FF:FF:FF:FF")
					{
						info.Info = $"Who has {targetIP}? Tell {senderIP}";
						info.Destination = "Broadcast";
					}
					else info.Info = $"{senderIP} is at {info.Source}";
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.IpV6:
					info.Layers.IPInfo = "Internet Protocol Version 6";
					GetIpProtocol(packet, info);
					break;
				default:
					break;
			}
			info.Layers.EthernetInfo = $"Source: {packet.Ethernet.Source}\nDestination: {packet.Ethernet.Destination}";
		}

		private void GetIpProtocol(Packet packet, PacketInfo info)
		{
			switch (packet.Ethernet.IpV4.Protocol)
			{
				case IpV4Protocol.InternetControlMessageProtocol:
					IcmpDatagram icmp = packet.Ethernet.IpV4.Icmp;
					if (icmp != null)
					{
						info.Protocol = "ICMP";
						info.Info = "Echo (ping)";
						info.Layers.ICMPInfo = $"Checksum: {icmp.Checksum}";
					}
					break;
				case IpV4Protocol.Tcp:
					var tcp = packet.Ethernet.IpV4.Tcp;
					info.Protocol = "TCP";
					info.Info = $"{tcp.SourcePort} → {tcp.DestinationPort} [{GetFlags(tcp)}] " +
						$"Seq={tcp.SequenceNumber} Win={tcp.Window} Len={tcp.Length}";
					/////////////// HTTP Request//////////////////
					var header = tcp.Http.Header;
					if (header != null)
					{
						info.Protocol = "HTTP";
						info.Layers.HTTPInfo = "Header: " + header;
					}
					/////////////// TCP Layer//////////////////
					info.Layers.TCPInfo = $"Source Port: {tcp.SourcePort}\nDestination Port: {tcp.DestinationPort}" +
						$"\nSequence number: {tcp.SequenceNumber}\nNext sequence number: {tcp.NextSequenceNumber}" +
						$"\nAcknowledgement number: {tcp.AcknowledgmentNumber}\nHeader Length: {tcp.HeaderLength}" +
						$"\nWindow size value: {tcp.Window}\nChecksum: {tcp.Checksum}";
					break;
				case IpV4Protocol.Udp:
					UdpDatagram udp = packet.Ethernet.IpV4.Udp;
					info.Protocol = "UDP";
					info.Info = $"{udp.SourcePort} → {udp.DestinationPort} Len={udp.Length}";
					info.Layers.UDPInfo = $"Source Port: {udp.SourcePort}\nDestination Port: {udp.DestinationPort}" +
						$"\nLength: {udp.TotalLength}\nChecksum: {udp.Checksum}";
					break;
				case IpV4Protocol.InternetControlMessageProtocolForIpV6:
					info.Protocol = "ICMPv6";
					break;
				default:
					break;
			}
		}

		/// <summary>
		/// https://www.geeksforgeeks.org/tcp-flags/?ref=lbp
		/// </summary>
		/// <param name="tcp"></param>
		/// <returns></returns>
		private string GetFlags(TcpDatagram tcp)
		{
			string flags = "";
			if (tcp.IsAcknowledgment)
				flags += " ACK ";
			if (tcp.IsFin)
				flags += " FIN ";
			if (tcp.IsSynchronize)
				flags += " SYN ";
			if (tcp.IsReset)
				flags += " RST ";
			if (tcp.IsPush)
				flags += " PSH ";
			if (tcp.IsUrgent) // Gói khẩn cấp
				flags += " URG ";
			return flags.Replace("  ", ", ").Trim();
		}

	}
}
