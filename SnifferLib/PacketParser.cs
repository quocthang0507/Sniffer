using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Text;

namespace SnifferLib
{
	public static class PacketParser
	{
		public static PacketInfo Parse(CaptureRecord capture, int id, double time)
		{
			ArgumentNullException.ThrowIfNull(capture);
			PacketInfo packet = Parse(capture.Data, capture.LinkLayer, id, time);
			packet.Capture = capture;
			packet.Length = capture.OriginalLength;
			return packet;
		}

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
				Buffer = new PacketBuff(bytes),
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
			info.SourceAddress = ip.SourceAddress;
			info.DestinationAddress = ip.DestinationAddress;
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
			info.SourceAddress = ip.SourceAddress;
			info.DestinationAddress = ip.DestinationAddress;
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
						info.Info = $"Type/Code: {icmp.TypeCode}";
						info.Layers.ICMPInfo = $"Checksum: {icmp.Checksum}";
					}
					break;
				case PacketDotNet.ProtocolType.IcmpV6:
					info.Protocol = "ICMPv6";
					IcmpV6Packet? icmpv6 = ip.Extract<IcmpV6Packet>();
					if (icmpv6 is not null)
					{
						info.Info = $"{icmpv6.Type}, code {icmpv6.Code}";
						info.Layers.ICMPInfo = $"Type: {icmpv6.Type}\nCode: {icmpv6.Code}\nChecksum: {icmpv6.Checksum}";
					}
					break;
				case PacketDotNet.ProtocolType.Tcp:
					TcpPacket? tcp = ip.Extract<TcpPacket>();
					if (tcp is not null)
					{
						info.Protocol = "TCP";
						info.TransportProtocol = "TCP";
						info.SourcePort = tcp.SourcePort;
						info.DestinationPort = tcp.DestinationPort;
						info.Info = $"{tcp.SourcePort} → {tcp.DestinationPort} [{GetFlags(tcp)}] " +
							$"Seq={tcp.SequenceNumber} Win={tcp.WindowSize} Len={Math.Max(0, tcp.TotalPacketLength - tcp.DataOffset * 4)}";
						info.Layers.TCPInfo = $"Source Port: {tcp.SourcePort}\nDestination Port: {tcp.DestinationPort}" +
							$"\nSequence number: {tcp.SequenceNumber}\nNext sequence number: {tcp.SequenceNumber + Math.Max(0, tcp.TotalPacketLength - tcp.DataOffset * 4)}" +
							$"\nAcknowledgement number: {tcp.AcknowledgmentNumber}\nHeader Length: {tcp.DataOffset * 4}" +
							$"\nWindow size value: {tcp.WindowSize}\nChecksum: {tcp.Checksum}";
						ParseHttp(tcp, info);
						if (tcp.SourcePort == 53 || tcp.DestinationPort == 53)
							ParseDns(tcp.PayloadData, info, true);
					}
					break;
				case PacketDotNet.ProtocolType.Udp:
					UdpPacket? udp = ip.Extract<UdpPacket>();
					if (udp is not null)
					{
						info.Protocol = "UDP";
						info.TransportProtocol = "UDP";
						info.SourcePort = udp.SourcePort;
						info.DestinationPort = udp.DestinationPort;
						info.Info = $"{udp.SourcePort} → {udp.DestinationPort} Len={udp.Length}";
						info.Layers.UDPInfo = $"Source Port: {udp.SourcePort}\nDestination Port: {udp.DestinationPort}" +
							$"\nLength: {udp.Length}\nChecksum: {udp.Checksum}";
						if (udp.SourcePort == 53 || udp.DestinationPort == 53)
							ParseDns(udp.PayloadData, info, false);
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
			info.Info = firstLine;
			info.Layers.HTTPInfo = "Header: " + (headerEnd >= 0 ? text[..headerEnd] : text);
		}

		private static void ParseDns(byte[]? payload, PacketInfo info, bool tcp)
		{
			if (payload is null)
				return;
			int offset = tcp ? 2 : 0;
			if (payload.Length - offset < 12)
				return;
			if (tcp && ((payload[0] << 8) | payload[1]) > payload.Length - 2)
				return;

			int id = (payload[offset] << 8) | payload[offset + 1];
			bool response = (payload[offset + 2] & 0x80) != 0;
			int questions = (payload[offset + 4] << 8) | payload[offset + 5];
			int answers = (payload[offset + 6] << 8) | payload[offset + 7];
			string description = $"{(response ? "response" : "query")} 0x{id:x4}";
			int index = offset + 12;
			if (questions > 0)
			{
				var labels = new List<string>();
				while (index < payload.Length && payload[index] != 0)
				{
					int length = payload[index++];
					if (length > 63 || index + length > payload.Length)
						return;
					labels.Add(Encoding.ASCII.GetString(payload, index, length));
					index += length;
				}
				if (index + 5 > payload.Length)
					return;
				description += " " + string.Join(".", labels);
			}
			info.Protocol = "DNS";
			info.Info = "Standard " + description;
			info.Layers.DNSInfo = $"Transaction ID: 0x{id:x4}\nType: {(response ? "Response" : "Query")}\nQuestions: {questions}\nAnswers: {answers}\n{description}";
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

		private static string FormatMacAddress(byte[] address)
		{
			return BitConverter.ToString(address);
		}
	}
}
