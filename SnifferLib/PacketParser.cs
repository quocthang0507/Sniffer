using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Text;

namespace SnifferLib
{
	internal static class PacketParser
	{
		public static PacketInfo Parse(byte[] bytes, LinkLayers linkLayer, int id, double time)
		{
			ArgumentNullException.ThrowIfNull(bytes);

			PacketInfo info = new PacketInfo
			{
				ID = id,
				Time = time,
				Source = string.Empty,
				Destination = string.Empty,
				Protocol = "Unknown",
				Buffer = new PacketBuff(FormatHex(bytes), Encoding.UTF8.GetString(bytes)),
				Length = bytes.Length,
				Info = string.Empty,
				Layers = new PacketLayer()
			};

			if (linkLayer != LinkLayers.Ethernet)
			{
				info.Protocol = $"Unsupported link layer ({linkLayer})";
				return info;
			}

			if (bytes.Length < 14)
			{
				info.Protocol = "Malformed Ethernet";
				info.Info = "Frame is shorter than an Ethernet header.";
				return info;
			}

			try
			{
				Packet packet = Packet.ParsePacket(linkLayer, bytes);
				EthernetPacket? ethernet = packet.Extract<EthernetPacket>();
				if (ethernet is null)
				{
					info.Protocol = "Malformed Ethernet";
					info.Info = "Ethernet header could not be decoded.";
					return info;
				}

				info.Source = FormatMacAddress(ethernet.SourceHardwareAddress.GetAddressBytes());
				info.Destination = FormatMacAddress(ethernet.DestinationHardwareAddress.GetAddressBytes());
				info.Layers.EthernetInfo = $"Source: {info.Source}\nDestination: {info.Destination}";

				switch (ethernet.Type)
				{
					case EthernetType.Arp:
						ParseArp(packet, info);
						break;
					case EthernetType.IPv4:
						ParseIPv4(packet, info);
						break;
					case EthernetType.IPv6:
						ParseIPv6(packet, info);
						break;
					default:
						info.Protocol = $"EtherType 0x{(ushort)ethernet.Type:X4}";
						break;
				}
			}
			catch (Exception exception) when (
				exception is ArgumentException or
				IndexOutOfRangeException or
				InvalidOperationException or
				NotSupportedException)
			{
				info.Protocol = "Malformed";
				info.Info = "Frame is malformed or truncated and could not be decoded.";
			}

			return info;
		}

		private static void ParseArp(Packet packet, PacketInfo info)
		{
			ArpPacket? arp = packet.Extract<ArpPacket>();
			if (arp is null)
			{
				info.Protocol = "Malformed ARP";
				return;
			}

			info.Protocol = "ARP";
			info.Source = arp.SenderProtocolAddress.ToString();
			info.Destination = arp.TargetProtocolAddress.ToString();
			info.Layers.IPInfo = "Address Resolution Protocol";

			if (arp.Operation == ArpOperation.Request)
			{
				info.Info = $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}";
			}
			else if (arp.Operation == ArpOperation.Response)
			{
				info.Info = $"{arp.SenderProtocolAddress} is at {FormatMacAddress(arp.SenderHardwareAddress.GetAddressBytes())}";
			}
			else
			{
				info.Info = arp.Operation.ToString();
			}
		}

		private static void ParseIPv4(Packet packet, PacketInfo info)
		{
			IPv4Packet? ip = packet.Extract<IPv4Packet>();
			if (ip is null)
			{
				info.Protocol = "Malformed IPv4";
				return;
			}

			info.Source = ip.SourceAddress.ToString();
			info.Destination = ip.DestinationAddress.ToString();
			info.Protocol = ip.Protocol.ToString().ToUpperInvariant();
			info.Layers.IPInfo = $"Internet Protocol Version 4\nSource: {ip.SourceAddress}\nDestination: {ip.DestinationAddress}" +
				$"\nHeader Length: {ip.HeaderLength * 4}" +
				$"\nTotal Length: {ip.TotalLength}" +
				$"\nTime to live: {ip.TimeToLive}";

			if (ip.FragmentOffset == 0)
			{
				ParseTransport(ip, info);
			}
		}

		private static void ParseIPv6(Packet packet, PacketInfo info)
		{
			IPv6Packet? ip = packet.Extract<IPv6Packet>();
			if (ip is null)
			{
				info.Protocol = "Malformed IPv6";
				return;
			}

			info.Source = ip.SourceAddress.ToString();
			info.Destination = ip.DestinationAddress.ToString();
			info.Protocol = ip.Protocol == PacketDotNet.ProtocolType.IcmpV6 ? "ICMPv6" : ip.Protocol.ToString().ToUpperInvariant();
			info.Layers.IPInfo = $"Internet Protocol Version 6\nSource: {ip.SourceAddress}\nDestination: {ip.DestinationAddress}" +
				$"\nPayload Length: {ip.PayloadLength}" +
				$"\nHop Limit: {ip.HopLimit}";

			ParseTransport(ip, info);
		}

		private static void ParseTransport(IPPacket ip, PacketInfo info)
		{
			switch (ip.Protocol)
			{
				case PacketDotNet.ProtocolType.Icmp:
					IcmpV4Packet? icmp = ip.Extract<IcmpV4Packet>();
					if (icmp is not null)
					{
						info.Protocol = "ICMP";
						info.Info = "Echo (ping)";
						info.Layers.ICMPInfo = $"Checksum: {icmp.Checksum}";
					}
					break;
				case PacketDotNet.ProtocolType.IcmpV6:
					info.Protocol = "ICMPv6";
					break;
				case PacketDotNet.ProtocolType.Tcp:
					TcpPacket? tcp = ip.Extract<TcpPacket>();
					if (tcp is not null)
					{
						info.Protocol = "TCP";
						info.Info = $"{tcp.SourcePort} → {tcp.DestinationPort} [{GetFlags(tcp)}] " +
							$"Seq={tcp.SequenceNumber} Win={tcp.WindowSize} Len={Math.Max(0, tcp.TotalPacketLength - tcp.DataOffset * 4)}";
						info.Layers.TCPInfo = $"Source Port: {tcp.SourcePort}\nDestination Port: {tcp.DestinationPort}" +
							$"\nSequence number: {tcp.SequenceNumber}\nNext sequence number: {tcp.SequenceNumber + Math.Max(0, tcp.TotalPacketLength - tcp.DataOffset * 4)}" +
							$"\nAcknowledgement number: {tcp.AcknowledgmentNumber}\nHeader Length: {tcp.DataOffset * 4}" +
							$"\nWindow size value: {tcp.WindowSize}\nChecksum: {tcp.Checksum}";
						ParseHttp(tcp, info);
					}
					break;
				case PacketDotNet.ProtocolType.Udp:
					UdpPacket? udp = ip.Extract<UdpPacket>();
					if (udp is not null)
					{
						info.Protocol = "UDP";
						info.Info = $"{udp.SourcePort} → {udp.DestinationPort} Len={udp.Length}";
						info.Layers.UDPInfo = $"Source Port: {udp.SourcePort}\nDestination Port: {udp.DestinationPort}" +
							$"\nLength: {udp.Length}\nChecksum: {udp.Checksum}";
					}
					break;
			}
		}

		private static void ParseHttp(TcpPacket tcp, PacketInfo info)
		{
			if (!tcp.HasPayloadData)
			{
				return;
			}

			byte[]? payload = tcp.PayloadData;
			if (payload is null || payload.Length == 0)
			{
				return;
			}

			string text = Encoding.ASCII.GetString(payload);
			int lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
			string firstLine = lineEnd >= 0 ? text[..lineEnd] : text;
			if (!firstLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("DELETE ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("OPTIONS ", StringComparison.OrdinalIgnoreCase) &&
				!firstLine.StartsWith("PATCH ", StringComparison.OrdinalIgnoreCase))
			{
				return;
			}

			int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
			info.Protocol = "HTTP";
			info.Layers.HTTPInfo = "Header: " + (headerEnd >= 0 ? text[..headerEnd] : text);
		}

		private static string GetFlags(TcpPacket tcp)
		{
			List<string> flags = new List<string>();
			if (tcp.Acknowledgment)
				flags.Add("ACK");
			if (tcp.Finished)
				flags.Add("FIN");
			if (tcp.Synchronize)
				flags.Add("SYN");
			if (tcp.Reset)
				flags.Add("RST");
			if (tcp.Push)
				flags.Add("PSH");
			if (tcp.Urgent)
				flags.Add("URG");

			return string.Join(", ", flags);
		}

		private static string FormatHex(byte[] bytes)
		{
			StringBuilder builder = new StringBuilder(bytes.Length * 4);
			for (int i = 0; i < bytes.Length; i++)
			{
				builder.Append(bytes[i].ToString("x2")).Append("  ");
				if ((i + 1) % 16 == 0)
					builder.Append('\n');
			}
			return builder.ToString();
		}

		private static string FormatMacAddress(byte[] address)
		{
			return BitConverter.ToString(address);
		}
	}
}
