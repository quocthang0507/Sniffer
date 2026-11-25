using System;
using System.Net;
using System.Net.Sockets;

namespace SnifferLib
{
	public static class DisplayFilter
	{
		public static Func<PacketInfo, bool> Parse(string expression)
		{
			ArgumentNullException.ThrowIfNull(expression);
			if (string.IsNullOrWhiteSpace(expression))
				return _ => true;
			var parser = new Parser(expression);
			var result = parser.ParseOr();
			parser.SkipWhitespace();
			if (!parser.AtEnd)
				throw new FormatException("Unexpected text in display filter.");
			return result;
		}

		private sealed class Parser
		{
			private readonly string text;
			private int position;

			public Parser(string text) => this.text = text;
			public bool AtEnd => position == text.Length;

			public void SkipWhitespace()
			{
				while (!AtEnd && char.IsWhiteSpace(text[position]))
					position++;
			}

			private bool Consume(string token)
			{
				SkipWhitespace();
				if (!text.AsSpan(position).StartsWith(token, StringComparison.Ordinal))
					return false;
				position += token.Length;
				return true;
			}

			public Func<PacketInfo, bool> ParseOr()
			{
				var left = ParseAnd();
				while (Consume("||"))
				{
					var previous = left;
					var right = ParseAnd();
					left = packet => previous(packet) || right(packet);
				}
				return left;
			}

			private Func<PacketInfo, bool> ParseAnd()
			{
				var left = ParseTerm();
				while (Consume("&&"))
				{
					var previous = left;
					var right = ParseTerm();
					left = packet => previous(packet) && right(packet);
				}
				return left;
			}

			private Func<PacketInfo, bool> ParseTerm()
			{
				if (Consume("("))
				{
					var inner = ParseOr();
					if (!Consume(")"))
						throw new FormatException("Missing closing parenthesis.");
					return inner;
				}

				string field = ReadToken().ToLowerInvariant();
				if (field.Length == 0)
					throw new FormatException("Expected a protocol or field.");
				if (field is "ip.addr" or "tcp.port" or "udp.port")
				{
					if (!Consume("=="))
						throw new FormatException($"Expected == after {field}.");
					string value = ReadToken();
					if (field == "ip.addr")
					{
						if (!IPAddress.TryParse(value, out var address))
							throw new FormatException("Expected a valid IP address.");
						return packet => address.Equals(packet.SourceAddress) || address.Equals(packet.DestinationAddress);
					}
					if (!ushort.TryParse(value, out ushort port))
						throw new FormatException("Expected a port between 0 and 65535.");
					string transport = field == "tcp.port" ? "TCP" : "UDP";
					return packet => packet.TransportProtocol == transport &&
						(packet.SourcePort == port || packet.DestinationPort == port);
				}

				return field switch
				{
					"ip" => packet => packet.SourceAddress?.AddressFamily == AddressFamily.InterNetwork,
					"ipv6" => packet => packet.SourceAddress?.AddressFamily == AddressFamily.InterNetworkV6,
					"arp" => packet => packet.Protocol == "ARP",
					"tcp" => packet => packet.TransportProtocol == "TCP",
					"udp" => packet => packet.TransportProtocol == "UDP",
					"icmp" => packet => packet.Protocol == "ICMP",
					"icmpv6" => packet => packet.Protocol == "ICMPv6",
					"dns" => packet => packet.Layers.DNSInfo is not null,
					"http" => packet => packet.Layers.HTTPInfo is not null,
					_ => throw new FormatException($"Unsupported filter: {field}.")
				};
			}

			private string ReadToken()
			{
				SkipWhitespace();
				int start = position;
				while (!AtEnd && !char.IsWhiteSpace(text[position]) &&
					text[position] is not ('(' or ')' or '&' or '|' or '='))
					position++;
				return text[start..position];
			}
		}
	}
}
