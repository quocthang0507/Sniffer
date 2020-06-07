using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace SnifferLib
{

	public class SnifferClass
	{
		private PacketDevice selectedDevice;
		private IList<LivePacketDevice> devices;
		private Stopwatch stopwatch;

		/// <summary>
		/// Danh sách các gói tin đã bắt được
		/// </summary>
		public BindingList<PacketInfo> packets { get; set; }
		/// <summary>
		/// Hàm ủy quyền thêm gói tin vào data grid
		/// </summary>
		/// <param name="packet"></param>
		public delegate void AddItemToDataGrid(PacketInfo packet);
		public AddItemToDataGrid UpdateDataGrid;

		/// <summary>
		/// Lấy danh sách card mạng trong máy tính
		/// </summary>
		/// <returns></returns>
		public List<string> GetInterfaces()
		{
			devices = LivePacketDevice.AllLocalMachine;
			List<string> result = new List<string>();
			foreach (var device in devices)
			{
				string name = device.Description;
				string[] array = name.Split('\'');
				result.Add(array[1]);
			}
			return result;
		}

		/// <summary>
		/// Lựa chọn card mạng theo số thứ tự
		/// </summary>
		/// <param name="index"></param>
		public void GetInterface(int index)
		{
			selectedDevice = devices[index];
		}

		/// <summary>
		/// Lấy tên của card mạng đang được lựa chọn
		/// </summary>
		/// <returns></returns>
		public string GetNameInterface()
		{
			return selectedDevice.Description.Split('\'')[1];
		}

		/// <summary>
		/// Thêm sự kiện khi một gói tin đã thêm vào danh sách. Bắt form cập nhập từ bên này. Bên kia k thể chủ động , mình chu
		/// </summary>
		private void AddEventWhenNewItemAdded()
		{
			packets.ListChanged += (sender, e) =>
			  {
				  UpdateDataGrid(packets[packets.Count - 1]);
			  };
		}

		/// <summary>
		/// Bắt đầu quá trình bắt gói tin
		/// </summary>
		public void Start()
		{
			if (devices.Count == 0)
			{
				throw new AggregateException("No interfaces found! Make sure WinPcap is installed.");
			}
			packets = new BindingList<PacketInfo>();
			AddEventWhenNewItemAdded();
			stopwatch = new Stopwatch();
			using (PacketCommunicator communicator =
				selectedDevice.Open(65536,                                  // 2^16byte, 64kb, max size của gói tin
									PacketDeviceOpenAttributes.Promiscuous, // Chế độ bắt tất cả gói tin đang truyền trên mạng
									1000))                                  // Thời gian chờ tối đa
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
			// Lấy thông tin cơ bản
			PacketInfo info = new PacketInfo();
			info.ID = packets.Count + 1; // ban đầu là 0 id =1
			info.Time = stopwatch.Elapsed.TotalSeconds;
			IpV4Datagram ip = packet.Ethernet.IpV4;
			TcpDatagram tcp = ip.Tcp;
			info.Source = ip.Source.ToString();
			info.Destination = ip.Destination.ToString();
			info.Protocol = packet.Ethernet.IpV4.Protocol.ToString();
			info.Length = packet.Length;
			string hex = packet.BytesSequenceToHexadecimalString();
			info.Buffer = new PacketBuff(ProcessString(hex), HextoString(hex));
			GetMoreInfo(packet, info);
			packets.Add(info);
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

		/// <summary>
		/// Lấy thêm thông tin cho từng loại giao thức
		/// </summary>
		/// <param name="packet"></param>
		/// <param name="info"></param>
		private void GetMoreInfo(Packet packet, PacketInfo info)
		{
			switch (packet.Ethernet.EtherType)
			{
				case PcapDotNet.Packets.Ethernet.EthernetType.None:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.IpV4:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.Arp:
					info.Protocol = "ARP";
					var arp = packet.Ethernet.Arp;
					info.Source = packet.Ethernet.Source.ToString();
					var senderIP = arp.SenderProtocolIpV4Address;
					info.Destination = packet.Ethernet.Destination.ToString();
					var targetIP = arp.TargetProtocolIpV4Address;
					if (info.Destination == "FF:FF:FF:FF:FF:FF")
					{
						info.Info = $"Who has {targetIP}? Tell {senderIP}";
						info.Destination = "Broadcast";
					}
					info.Info = $"{senderIP} is at {info.Source}";
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.ReverseArp:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.AppleTalk:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.AppleTalkArp:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.VLanTaggedFrame:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.NovellInternetworkPacketExchange:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.Novell:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.IpV6:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.MacControl:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.PointToPointProtocol:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.CobraNet:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.MultiprotocolLabelSwitchingUnicast:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.MultiprotocolLabelSwitchingMulticast:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.PointToPointProtocolOverEthernetDiscoveryStage:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.PointToPointProtocolOverEthernetSessionStage:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.ExtensibleAuthenticationProtocolOverLan:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.HyperScsi:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.AtaOverEthernet:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.EtherCatProtocol:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.ProviderBridging:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.AvbTransportProtocol:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.SerialRealTimeCommunicationSystemIii:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.CircuitEmulationServicesOverEthernet:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.HomePlug:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.MacSecurity:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.PrecisionTimeProtocol:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.ConnectivityFaultManagementOrOperationsAdministrationManagement:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.FibreChannelOverEthernet:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.FibreChannelOverEthernetInitializationProtocol:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.QInQ:
					break;
				case PcapDotNet.Packets.Ethernet.EthernetType.VeritasLowLatencyTransport:
					break;
				default:
					break;
			}
		}

	}
}
