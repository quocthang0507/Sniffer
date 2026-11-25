using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SnifferLib
{
	public static class PacketAnalysis
	{
		private const long MaxFollowCapturedBytes = 16 * 1024 * 1024;
		public static bool MatchesSearch(PacketInfo packet, string query)
		{
			ArgumentNullException.ThrowIfNull(packet);
			ArgumentException.ThrowIfNullOrWhiteSpace(query);
			if (packet.Source.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				packet.Destination.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				packet.Protocol.Contains(query, StringComparison.OrdinalIgnoreCase) ||
				packet.Info.Contains(query, StringComparison.OrdinalIgnoreCase))
				return true;
			byte[]? data = packet.Capture?.Data;
			if (data is null || query.Any(c => c > 127))
				return false;
			for (int i = 0; i <= data.Length - query.Length; i++)
			{
				int j = 0;
				while (j < query.Length && char.ToUpperInvariant((char)data[i + j]) == char.ToUpperInvariant(query[j]))
					j++;
				if (j == query.Length)
					return true;
			}
			return false;
		}

		public static string Statistics(IEnumerable<PacketInfo> packets)
		{
			ArgumentNullException.ThrowIfNull(packets);
			PacketInfo[] snapshot = packets.ToArray();
			var result = new StringBuilder();
			result.AppendLine($"Packets: {snapshot.Length}");
			result.AppendLine($"Original bytes: {snapshot.Sum(p => (long)p.Length)}");
			result.AppendLine($"Captured bytes: {snapshot.Sum(p => (long)(p.Capture?.Data.Length ?? 0))}");
			result.AppendLine().AppendLine("Protocols (highest decoded layer):");
			foreach (var group in snapshot.GroupBy(p => p.Protocol).OrderByDescending(g => g.Count()).ThenBy(g => g.Key))
				result.AppendLine($"{group.Key}: {group.Count()} packets, {group.Sum(p => (long)p.Length)} bytes");
			result.AppendLine().AppendLine("Endpoints (source + destination appearances; top 50):");
			foreach (var group in snapshot.SelectMany(p => new[] { p.Source, p.Destination })
				.Where(address => !string.IsNullOrEmpty(address)).GroupBy(address => address)
				.OrderByDescending(g => g.Count()).ThenBy(g => g.Key).Take(50))
				result.AppendLine($"{group.Key}: {group.Count()} appearances");
			return result.ToString();
		}

		private sealed record Segment(int Index, bool Forward, uint Sequence, bool Syn, bool Ack, byte[] Payload, bool Truncated);

		public static string FollowConversation(IReadOnlyList<PacketInfo> packets, PacketInfo selected)
		{
			ArgumentNullException.ThrowIfNull(packets);
			ArgumentNullException.ThrowIfNull(selected);
			if (selected.SourceAddress is null || selected.DestinationAddress is null ||
				selected.SourcePort is null || selected.DestinationPort is null ||
				selected.TransportProtocol is not ("TCP" or "UDP"))
				throw new InvalidOperationException("Select a decoded TCP or UDP packet.");
			int selectedIndex = -1;
			var segments = new List<Segment>();
			int undecodable = 0;
			long capturedBytes = 0;
			for (int i = 0; i < packets.Count; i++)
			{
				PacketInfo packet = packets[i];
				if (packet.TransportProtocol != selected.TransportProtocol)
					continue;
				bool forward = Equals(packet.SourceAddress, selected.SourceAddress) &&
					Equals(packet.DestinationAddress, selected.DestinationAddress) &&
					packet.SourcePort == selected.SourcePort && packet.DestinationPort == selected.DestinationPort;
				bool reverse = Equals(packet.SourceAddress, selected.DestinationAddress) &&
					Equals(packet.DestinationAddress, selected.SourceAddress) &&
					packet.SourcePort == selected.DestinationPort && packet.DestinationPort == selected.SourcePort;
				if (!forward && !reverse)
					continue;
				if (ReferenceEquals(packet, selected))
					selectedIndex = i;
				if (packet.Capture is null)
				{
					undecodable++;
					continue;
				}
				capturedBytes += packet.Capture.Data.Length;
				if (capturedBytes > MaxFollowCapturedBytes)
					throw new InvalidOperationException("Conversation exceeds the 16 MiB analysis limit. Narrow the capture before following it.");
				try
				{
					Packet parsed = Packet.ParsePacket(packet.Capture.LinkLayer, packet.Capture.Data);
					if (selected.TransportProtocol == "TCP" && parsed.Extract<TcpPacket>() is TcpPacket tcp)
						segments.Add(new Segment(i, forward, tcp.SequenceNumber, tcp.Synchronize, tcp.Acknowledgment,
							tcp.PayloadData ?? Array.Empty<byte>(), packet.Capture.Data.Length < packet.Capture.OriginalLength));
					else if (selected.TransportProtocol == "UDP" && parsed.Extract<UdpPacket>() is UdpPacket udp)
						segments.Add(new Segment(i, forward, 0, false, false,
							udp.PayloadData ?? Array.Empty<byte>(), packet.Capture.Data.Length < packet.Capture.OriginalLength));
					else
						undecodable++;
				}
				catch (Exception exception) when (exception is ArgumentException or IndexOutOfRangeException or InvalidOperationException or NotSupportedException)
				{
					undecodable++;
				}
			}
			if (selectedIndex < 0 || !segments.Any(s => s.Index == selectedIndex))
				throw new InvalidOperationException("The selected packet's transport payload is unavailable.");
			if (selected.TransportProtocol == "TCP")
			{
				var starts = new List<int> { 0 };
				for (int i = 0; i < segments.Count; i++)
				{
					var segment = segments[i];
					if (!segment.Syn || segment.Ack)
						continue;
					int start = starts[starts.Count - 1];
					bool retransmission = i > start && segments[start].Syn && !segments[start].Ack &&
						segments[start].Forward == segment.Forward && segments[start].Sequence == segment.Sequence &&
						!segments.Skip(start + 1).Take(i - start - 1).Any(s => !s.Syn);
					if (i > start && !retransmission)
						starts.Add(i);
				}
				int chosen = segments.FindIndex(s => s.Index == selectedIndex);
				int range = starts.FindLastIndex(start => start <= chosen);
				int end = range + 1 < starts.Count ? starts[range + 1] : segments.Count;
				segments = segments.GetRange(starts[range], end - starts[range]);
			}
			var result = new StringBuilder();
			result.AppendLine($"{selected.TransportProtocol}: {selected.SourceAddress}:{selected.SourcePort} <-> {selected.DestinationAddress}:{selected.DestinationPort}");
			result.AppendLine("Printable ASCII shown; non-printable bytes are '.', encrypted data is not decrypted.");
			if (selected.TransportProtocol == "TCP")
			{
				result.AppendLine("TCP is reassembled separately by direction using sequence numbers. Missing bytes are marked; IP fragments are not reassembled. Captures without a handshake or reused endpoints may be ambiguous.");
				AppendTcp(result, segments.Where(s => s.Forward), "Selected direction");
				AppendTcp(result, segments.Where(s => !s.Forward), "Reverse direction");
			}
			else
			{
				result.AppendLine("UDP datagrams are shown in capture order; endpoint reuse cannot be distinguished.");
				foreach (Segment segment in segments)
				{
					result.AppendLine($"\nPacket {packets[segment.Index].ID} ({(segment.Forward ? "selected direction" : "reverse direction")}):");
					AppendAscii(result, segment.Payload, 0, segment.Payload.Length);
				}
			}
			if (segments.Any(s => s.Truncated)) result.AppendLine("\nWarning: one or more packets were truncated during capture.");
			if (undecodable > 0) result.AppendLine($"\nWarning: {undecodable} matching packets could not be decoded.");
			return result.ToString();
		}

		private static void AppendTcp(StringBuilder result, IEnumerable<Segment> input, string direction)
		{
			var segments = input.Where(s => s.Payload.Length != 0).ToArray();
			result.AppendLine($"\n{direction}:");
			if (segments.Length == 0) { result.AppendLine("(no payload)"); return; }
			uint anchor = unchecked(segments[0].Sequence + (segments[0].Syn ? 1u : 0u));
			var ordered = segments.Select(s => (Segment: s, Offset: (long)unchecked((int)(s.Sequence + (s.Syn ? 1u : 0u) - anchor))))
				.OrderBy(s => s.Offset).ThenBy(s => s.Segment.Index);
			long? end = null;
			foreach (var item in ordered)
			{
				if (end.HasValue && item.Offset > end.Value)
					result.Append($"\n[Missing {item.Offset - end.Value} bytes]\n");
				int skip = end.HasValue ? (int)Math.Min(item.Segment.Payload.Length, Math.Max(0, end.Value - item.Offset)) : 0;
				AppendAscii(result, item.Segment.Payload, skip, item.Segment.Payload.Length - skip);
				end = Math.Max(end ?? item.Offset, item.Offset + item.Segment.Payload.Length);
			}
			result.AppendLine();
		}

		private static void AppendAscii(StringBuilder result, byte[] data, int offset, int count)
		{
			for (int i = offset; i < offset + count; i++)
				result.Append(data[i] is >= 32 and <= 126 || data[i] is 10 or 13 or 9 ? (char)data[i] : '.');
		}
	}
}
