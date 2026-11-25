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
				if (Consume("!"))
				{
					var inner = ParseTerm();
					return packet => !inner(packet);
				}
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
				if (field is "ip.addr" or "ip.src" or "ip.dst" or "ipv6.addr" or "ipv6.src" or "ipv6.dst")
				{
					bool equal = ReadEquality(field);
					string value = ReadToken();
					if (field == "ip.addr")
					{
						if (!IPAddress.TryParse(value, out var address))
							throw new FormatException("Expected a valid IP address.");
						return packet => packet.SourceAddress is not null && packet.DestinationAddress is not null &&
							((address.Equals(packet.SourceAddress) || address.Equals(packet.DestinationAddress)) == equal);
					}
					if (!IPAddress.TryParse(value, out var target) ||
						target.AddressFamily != (field.StartsWith("ipv6", StringComparison.Ordinal) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork))
						throw new FormatException($"Expected a valid {(field.StartsWith("ipv6", StringComparison.Ordinal) ? "IPv6" : "IPv4")} address.");
					return packet =>
					{
						if (packet.SourceAddress?.AddressFamily != target.AddressFamily || packet.DestinationAddress?.AddressFamily != target.AddressFamily)
							return false;
						bool matches = field.EndsWith(".src", StringComparison.Ordinal) ? target.Equals(packet.SourceAddress) :
							field.EndsWith(".dst", StringComparison.Ordinal) ? target.Equals(packet.DestinationAddress) :
							target.Equals(packet.SourceAddress) || target.Equals(packet.DestinationAddress);
						return matches == equal;
					};
				}
				if (field is "tcp.port" or "tcp.srcport" or "tcp.dstport" or "udp.port" or "udp.srcport" or "udp.dstport" or "frame.len" or "frame.number")
				{
					string comparison = ReadComparison(field);
					string value = ReadToken();
					int maximum = field.StartsWith("frame.", StringComparison.Ordinal) ? int.MaxValue : ushort.MaxValue;
					if (!int.TryParse(value, out int number) || number < 0 || number > maximum)
						throw new FormatException($"Expected a number between 0 and {maximum}.");
					return packet =>
					{
						if (field == "frame.len") return Compare(packet.Length, number, comparison);
						if (field == "frame.number") return Compare(packet.ID, number, comparison);
						if (packet.TransportProtocol != (field.StartsWith("tcp.", StringComparison.Ordinal) ? "TCP" : "UDP") ||
							packet.SourcePort is null || packet.DestinationPort is null)
							return false;
						if (field.EndsWith(".srcport", StringComparison.Ordinal)) return Compare(packet.SourcePort.Value, number, comparison);
						if (field.EndsWith(".dstport", StringComparison.Ordinal)) return Compare(packet.DestinationPort.Value, number, comparison);
						if (comparison == "!=")
							return Compare(packet.SourcePort.Value, number, comparison) && Compare(packet.DestinationPort.Value, number, comparison);
						return Compare(packet.SourcePort.Value, number, comparison) || Compare(packet.DestinationPort.Value, number, comparison);
					};
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

			private bool ReadEquality(string field)
			{
				if (Consume("==")) return true;
				if (Consume("!=")) return false;
				throw new FormatException($"Expected == or != after {field}.");
			}

			private string ReadComparison(string field)
			{
				foreach (string op in new[] { "==", "!=", "<=", ">=", "<", ">" })
					if (Consume(op)) return op;
				throw new FormatException($"Expected a comparison after {field}.");
			}

			private static bool Compare(int actual, int expected, string op) => op switch
			{
				"==" => actual == expected,
				"!=" => actual != expected,
				"<" => actual < expected,
				"<=" => actual <= expected,
				">" => actual > expected,
				">=" => actual >= expected,
				_ => throw new InvalidOperationException("Unknown comparison.")
			};

			private string ReadToken()
			{
				SkipWhitespace();
				int start = position;
				while (!AtEnd && !char.IsWhiteSpace(text[position]) &&
					text[position] is not ('(' or ')' or '&' or '|' or '=' or '!' or '<' or '>'))
					position++;
				return text[start..position];
			}
		}
	}
}
