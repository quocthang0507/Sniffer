using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
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
		private IList<LivePacketDevice> winpcapDevices;
		private PacketDevice selectedWinpcapDevice;
		private List<NetworkInterface> devices;
		private NetworkInterface selectedDevice;
		private Stopwatch stopwatch;
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
				if (!@interface.Name.Contains("Loopback"))
					values.Add($"{@interface.Description} - {@interface.Name} - {@interface.Id}");
			}
			return values;
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
		/// Phân tích gói tin và cho vào danh sách gói tin đã bắt được
		/// </summary>
		/// <param name="packet">Gói tin đang được xử lý</param>
		private void PacketHandler(Packet packet)
		{
			// Lấy thông tin cơ bản
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
			GetEthernetType(packet, info);
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

		private void GetIPv4Info(Packet packet, PacketInfo info)
		{
			switch (packet.Ethernet.IpV4.Protocol)
			{
				case IpV4Protocol.IpV6HopByHopOption:
					break;
				case IpV4Protocol.InternetControlMessageProtocol:
					info.Protocol = "ICMP";
					break;
				case IpV4Protocol.InternetGroupManagementProtocol:
					break;
				case IpV4Protocol.GatewayToGateway:
					break;
				case IpV4Protocol.Ip:
					break;
				case IpV4Protocol.Stream:
					break;
				case IpV4Protocol.Tcp:
					var tcp = packet.Ethernet.IpV4.Tcp;
					info.Protocol = "TCP";
					info.Info = $"{tcp.SourcePort} → {tcp.DestinationPort} [{GetFlags(tcp)}] Seq={tcp.SequenceNumber} Win={tcp.Window} Len={tcp.Length}";
					break;
				case IpV4Protocol.Cbt:
					break;
				case IpV4Protocol.ExteriorGatewayProtocol:
					break;
				case IpV4Protocol.InteriorGatewayProtocol:
					break;
				case IpV4Protocol.BbnRccMonitoring:
					break;
				case IpV4Protocol.NetworkVoice:
					break;
				case IpV4Protocol.Pup:
					break;
				case IpV4Protocol.Argus:
					break;
				case IpV4Protocol.Emcon:
					break;
				case IpV4Protocol.CrossNetDebugger:
					break;
				case IpV4Protocol.Chaos:
					break;
				case IpV4Protocol.Udp:
					break;
				case IpV4Protocol.Multiplexing:
					break;
				case IpV4Protocol.DcnMeasurement:
					break;
				case IpV4Protocol.HostMonitoringProtocol:
					break;
				case IpV4Protocol.PacketRadioMeasurement:
					break;
				case IpV4Protocol.XeroxNsInternetDatagramProtocol:
					break;
				case IpV4Protocol.Trunk1:
					break;
				case IpV4Protocol.Trunk2:
					break;
				case IpV4Protocol.Leaf1:
					break;
				case IpV4Protocol.Leaf2:
					break;
				case IpV4Protocol.ReliableDatagramProtocol:
					break;
				case IpV4Protocol.InternetReliableTransactionProtocol:
					break;
				case IpV4Protocol.IsoTransportProtocolClass4:
					break;
				case IpV4Protocol.BulkDataTransferProtocol:
					break;
				case IpV4Protocol.MagneticFusionEnergyNetworkServicesProtocol:
					break;
				case IpV4Protocol.MeritInternodalProtocol:
					break;
				case IpV4Protocol.DatagramCongestionControlProtocol:
					break;
				case IpV4Protocol.ThirdPartyConnect:
					break;
				case IpV4Protocol.InterDomainPolicyRoutingProtocol:
					break;
				case IpV4Protocol.XpressTransportProtocol:
					break;
				case IpV4Protocol.DatagramDeliveryProtocol:
					break;
				case IpV4Protocol.InterDomainPolicyRoutingProtocolControlMessageTransportProtocol:
					break;
				case IpV4Protocol.TransportProtocolPlusPlus:
					break;
				case IpV4Protocol.Il:
					break;
				case IpV4Protocol.IpV6:
					info.Protocol = "IPv6";
					break;
				case IpV4Protocol.SourceDemandRoutingProtocol:
					break;
				case IpV4Protocol.IpV6Route:
					break;
				case IpV4Protocol.FragmentHeaderForIpV6:
					break;
				case IpV4Protocol.InterDomainRoutingProtocol:
					break;
				case IpV4Protocol.Rsvp:
					break;
				case IpV4Protocol.Gre:
					break;
				case IpV4Protocol.MobileHostRoutingProtocol:
					break;
				case IpV4Protocol.Bna:
					break;
				case IpV4Protocol.Esp:
					break;
				case IpV4Protocol.AuthenticationHeader:
					break;
				case IpV4Protocol.IntegratedNetLayerSecurityProtocol:
					break;
				case IpV4Protocol.Swipe:
					break;
				case IpV4Protocol.NArp:
					break;
				case IpV4Protocol.Mobile:
					break;
				case IpV4Protocol.TransportLayerSecurityProtocol:
					break;
				case IpV4Protocol.Skip:
					break;
				case IpV4Protocol.InternetControlMessageProtocolForIpV6:
					break;
				case IpV4Protocol.NoNextHeaderForIpV6:
					break;
				case IpV4Protocol.IpV6Opts:
					break;
				case IpV4Protocol.AnyHostInternal:
					break;
				case IpV4Protocol.Cftp:
					break;
				case IpV4Protocol.AnyLocalNetwork:
					break;
				case IpV4Protocol.SatnetAndBackroomExpak:
					break;
				case IpV4Protocol.Kryptolan:
					break;
				case IpV4Protocol.RemoteVirtualDiskProtocol:
					break;
				case IpV4Protocol.InternetPluribusPacketCore:
					break;
				case IpV4Protocol.AnyDistributedFileSystem:
					break;
				case IpV4Protocol.SatMon:
					break;
				case IpV4Protocol.Visa:
					break;
				case IpV4Protocol.InternetPacketCoreUtility:
					break;
				case IpV4Protocol.ComputerProtocolNetworkExecutive:
					break;
				case IpV4Protocol.ComputerProtocolHeartbeat:
					break;
				case IpV4Protocol.WangSpanNetwork:
					break;
				case IpV4Protocol.PacketVideoProtocol:
					break;
				case IpV4Protocol.BackroomSatMon:
					break;
				case IpV4Protocol.SunNd:
					break;
				case IpV4Protocol.WidebandMonitoring:
					break;
				case IpV4Protocol.WidebandExpak:
					break;
				case IpV4Protocol.IsoIp:
					break;
				case IpV4Protocol.VersatileMessageTransactionProtocol:
					break;
				case IpV4Protocol.SecureVersatileMessageTransactionProtocol:
					break;
				case IpV4Protocol.Vines:
					break;
				case IpV4Protocol.Ttp:
					break;
				case IpV4Protocol.NationalScienceFoundationNetworkInteriorGatewayProtocol:
					break;
				case IpV4Protocol.DissimilarGatewayProtocol:
					break;
				case IpV4Protocol.Tcf:
					break;
				case IpV4Protocol.EnhancedInteriorGatewayRoutingProtocol:
					break;
				case IpV4Protocol.OpenShortestPathFirst:
					break;
				case IpV4Protocol.SpriteRpc:
					break;
				case IpV4Protocol.LArp:
					break;
				case IpV4Protocol.MulticastTransportProtocol:
					break;
				case IpV4Protocol.Ax25:
					break;
				case IpV4Protocol.IpIp:
					break;
				case IpV4Protocol.MobileInternetworkingControlProtocol:
					break;
				case IpV4Protocol.SemaphoreCommunicationsSecondProtocol:
					break;
				case IpV4Protocol.EtherIp:
					break;
				case IpV4Protocol.EncapsulationHeader:
					break;
				case IpV4Protocol.AnyPrivateEncryptionScheme:
					break;
				case IpV4Protocol.Gmtp:
					break;
				case IpV4Protocol.IpsilonFlowManagementProtocol:
					break;
				case IpV4Protocol.PrivateNetworkToNetworkInterface:
					break;
				case IpV4Protocol.Pin:
					break;
				case IpV4Protocol.Aris:
					break;
				case IpV4Protocol.SpaceCommunicationsProtocolStandards:
					break;
				case IpV4Protocol.Qnx:
					break;
				case IpV4Protocol.ActiveNetworks:
					break;
				case IpV4Protocol.IpComp:
					break;
				case IpV4Protocol.SitaraNetworksProtocol:
					break;
				case IpV4Protocol.CompaqPeer:
					break;
				case IpV4Protocol.InternetworkPacketExchangeInIp:
					break;
				case IpV4Protocol.VirtualRouterRedundancyProtocol:
					break;
				case IpV4Protocol.PragmaticGeneralMulticastTransportProtocol:
					break;
				case IpV4Protocol.Any0HopProtocol:
					break;
				case IpV4Protocol.LayerTwoTunnelingProtocol:
					break;
				case IpV4Protocol.DiiDataExchange:
					break;
				case IpV4Protocol.InteractiveAgentTransferProtocol:
					break;
				case IpV4Protocol.ScheduleTransferProtocol:
					break;
				case IpV4Protocol.SpectraLinkRadioProtocol:
					break;
				case IpV4Protocol.Uti:
					break;
				case IpV4Protocol.SimpleMessageProtocol:
					break;
				case IpV4Protocol.Sm:
					break;
				case IpV4Protocol.PerformanceTransparencyProtocol:
					break;
				case IpV4Protocol.IsIsOverIpV4:
					break;
				case IpV4Protocol.Fire:
					break;
				case IpV4Protocol.CombatRadioTransportProtocol:
					break;
				case IpV4Protocol.CombatRadioUserDatagram:
					break;
				case IpV4Protocol.ServiceSpecificConnectionOrientedProtocolInAMultilinkAndConnectionlessEnvironment:
					break;
				case IpV4Protocol.Iplt:
					break;
				case IpV4Protocol.SecurePacketShield:
					break;
				case IpV4Protocol.Pipe:
					break;
				case IpV4Protocol.StreamControlTransmissionProtocol:
					break;
				case IpV4Protocol.FibreChannel:
					break;
				case IpV4Protocol.RsvpE2EIgnore:
					break;
				case IpV4Protocol.MobilityHeader:
					break;
				case IpV4Protocol.UdpLite:
					break;
				case IpV4Protocol.MultiprotocolLabelSwitchingInIp:
					break;
				case IpV4Protocol.MobileAdHocNetwork:
					break;
				case IpV4Protocol.Hip:
					break;
				default:
					break;
			}
		}

		private void GetEthernetType(Packet packet, PacketInfo info)
		{
			GetIPv4Info(packet, info);
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
					else info.Info = $"{senderIP} is at {info.Source}";
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
					info.Protocol = "IPv6";
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

		/// <summary>
		/// Lựa chọn card mạng theo số thứ tự
		/// </summary>
		/// <param name="index"></param>
		public void SetSelectedInterface(int index)
		{
			selectedDevice = devices[index];
			SelectedNameDevice = selectedDevice.Description;
			string id = selectedDevice.Id.Replace("{", "").Replace("}", "");
			selectedWinpcapDevice = winpcapDevices.First(d => d.Name.Contains(id));
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
				selectedWinpcapDevice.Open(65536,                                  // 2^16byte, 64kb, max size của gói tin
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
	}
}
