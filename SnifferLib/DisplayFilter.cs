using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace SnifferLib
{
	public static class DisplayFilter
	{
		public static Func<PacketInfo, bool> Parse(string expression)
		{
			if (!TryParse(expression, out var filter, out var error))
				throw new FormatException(error);
			return filter;
		}

		public static bool TryParse(string expression, [NotNullWhen(true)] out Func<PacketInfo, bool>? filter,
			[NotNullWhen(false)] out string? error)
		{
			ArgumentNullException.ThrowIfNull(expression);
			if (string.IsNullOrWhiteSpace(expression))
			{
				filter = _ => true;
				error = null;
				return true;
			}
			var parser = new Parser(expression);
			var result = parser.ParseOr();
			parser.SkipWhitespace();
			if (result is null)
			{
				filter = null;
				error = parser.Error ?? throw new InvalidOperationException("Filter parser failed without an error.");
				return false;
			}
			if (!parser.AtEnd)
			{
				filter = null;
				error = "Unexpected text in display filter.";
				return false;
			}
			filter = result;
			error = null;
			return true;
		}

		private sealed class Parser
		{
			private readonly string text;
			private int position;
			public string? Error { get; private set; }

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

			private Func<PacketInfo, bool>? Fail(string message)
			{
				Error = message;
				return null;
			}

			public Func<PacketInfo, bool>? ParseOr()
			{
				var left = ParseAnd();
				if (left is null) return null;
				while (Consume("||"))
				{
					var previous = left;
					var right = ParseAnd();
					if (right is null) return null;
					left = packet => previous(packet) || right(packet);
				}
				return left;
			}

			private Func<PacketInfo, bool>? ParseAnd()
			{
				var left = ParseTerm();
				if (left is null) return null;
				while (Consume("&&"))
				{
					var previous = left;
					var right = ParseTerm();
					if (right is null) return null;
					left = packet => previous(packet) && right(packet);
				}
				return left;
			}

			private Func<PacketInfo, bool>? ParseTerm()
			{
				if (Consume("!"))
				{
					var inner = ParseTerm();
					if (inner is null) return null;
					return packet => !inner(packet);
				}
				if (Consume("("))
				{
					var inner = ParseOr();
					if (inner is null) return null;
					if (!Consume(")"))
						return Fail("Missing closing parenthesis.");
					return inner;
				}

				string field = ReadToken().ToLowerInvariant();
				if (field.Length == 0)
					return Fail("Expected a protocol or field.");
				if (field is "ip.addr" or "ip.src" or "ip.dst" or "ipv6.addr" or "ipv6.src" or "ipv6.dst")
				{
					bool equal;
					if (Consume("==")) equal = true;
					else if (Consume("!=")) equal = false;
					else return Fail($"Expected == or != after {field}.");
					string value = ReadToken();
					if (field == "ip.addr")
					{
						if (!IPAddress.TryParse(value, out var address))
							return Fail("Expected a valid IP address.");
						return packet => packet.SourceAddress is not null && packet.DestinationAddress is not null &&
							((address.Equals(packet.SourceAddress) || address.Equals(packet.DestinationAddress)) == equal);
					}
					if (!IPAddress.TryParse(value, out var target) ||
						target.AddressFamily != (field.StartsWith("ipv6", StringComparison.Ordinal) ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork))
						return Fail($"Expected a valid {(field.StartsWith("ipv6", StringComparison.Ordinal) ? "IPv6" : "IPv4")} address.");
					return packet =>
					{
						bool sourceAvailable = packet.SourceAddress?.AddressFamily == target.AddressFamily;
						bool destinationAvailable = packet.DestinationAddress?.AddressFamily == target.AddressFamily;
						if (field.EndsWith(".src", StringComparison.Ordinal) ? !sourceAvailable :
							field.EndsWith(".dst", StringComparison.Ordinal) ? !destinationAvailable : !sourceAvailable && !destinationAvailable)
							return false;
						bool matches = field.EndsWith(".src", StringComparison.Ordinal) ? target.Equals(packet.SourceAddress) :
							field.EndsWith(".dst", StringComparison.Ordinal) ? target.Equals(packet.DestinationAddress) :
							target.Equals(packet.SourceAddress) || target.Equals(packet.DestinationAddress);
						return matches == equal;
					};
				}
				if (field is "tcp.port" or "tcp.srcport" or "tcp.dstport" or "udp.port" or "udp.srcport" or "udp.dstport" or "frame.len" or "frame.number")
				{
					string? comparison = ReadComparison();
					if (comparison is null)
						return Fail($"Expected a comparison after {field}.");
					string value = ReadToken();
					int maximum = field.StartsWith("frame.", StringComparison.Ordinal) ? int.MaxValue : ushort.MaxValue;
					if (!int.TryParse(value, out int number) || number < 0 || number > maximum)
						return Fail($"Expected a number between 0 and {maximum}.");
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
					_ => Fail($"Unsupported filter: {field}.")
				};
			}

			private string? ReadComparison()
			{
				foreach (string op in new[] { "==", "!=", "<=", ">=", "<", ">" })
					if (Consume(op)) return op;
				return null;
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
