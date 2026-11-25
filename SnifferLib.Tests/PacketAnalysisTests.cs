using PacketDotNet;
using System;
using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace SnifferLib.Tests;

public class PacketAnalysisTests
{
	private static PacketInfo Packet(int id, bool tcp, bool reverse, uint sequence, byte flags, string payload)
	{
		byte[] body = Encoding.ASCII.GetBytes(payload);
		int transportLength = tcp ? 20 : 8;
		byte[] frame = new byte[14 + 20 + transportLength + body.Length];
		frame[12] = 8;
		frame[14] = 0x45;
		BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(16), (ushort)(frame.Length - 14));
		frame[22] = 64;
		frame[23] = tcp ? (byte)6 : (byte)17;
		frame[26] = 192; frame[28] = 2; frame[29] = reverse ? (byte)2 : (byte)1;
		frame[30] = 192; frame[32] = 2; frame[33] = reverse ? (byte)1 : (byte)2;
		BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(34), reverse ? (ushort)80 : (ushort)1234);
		BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(36), reverse ? (ushort)1234 : (ushort)80);
		if (tcp)
		{
			BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(38), sequence);
			frame[46] = 0x50;
			frame[47] = flags;
		}
		else
			BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(38), (ushort)(transportLength + body.Length));
		body.CopyTo(frame, 14 + 20 + transportLength);
		return PacketParser.Parse(new CaptureRecord(frame, LinkLayers.Ethernet, DateTimeOffset.UnixEpoch, frame.Length), id, id);
	}

	[Fact]
	public void Search_MatchesSummaryAndRawAsciiIgnoringCase()
	{
		var packet = Packet(1, false, false, 0, 0, "Hello payload");
		Assert.True(PacketAnalysis.MatchesSearch(packet, "192.0.2.1"));
		Assert.True(PacketAnalysis.MatchesSearch(packet, "PAYLOAD"));
		Assert.False(PacketAnalysis.MatchesSearch(packet, "not present"));
	}

	[Fact]
	public void Statistics_CountsProtocolsEndpointsAndBytes()
	{
		var packet = Packet(1, false, false, 0, 0, "hello");
		string result = PacketAnalysis.Statistics(new[] { packet, packet });
		Assert.Contains("Packets: 2", result);
		Assert.Contains("UDP: 2 packets", result);
		Assert.Contains("192.0.2.1: 2 appearances", result);
		Assert.Contains($"Original bytes: {packet.Length * 2}", result);
	}

	[Fact]
	public void FollowTcp_OrdersSegmentsRemovesRetransmissionsAndMarksGaps()
	{
		var first = Packet(1, true, false, 100, 0x10, "abc");
		var later = Packet(2, true, false, 106, 0x10, "ghi");
		var middle = Packet(3, true, false, 103, 0x10, "def");
		var retransmission = Packet(4, true, false, 103, 0x10, "def");
		var reverse = Packet(5, true, true, 500, 0x10, "reply");
		var gap = Packet(6, true, false, 112, 0x10, "end");
		string result = PacketAnalysis.FollowConversation(new[] { first, later, middle, retransmission, reverse, gap }, first);
		Assert.Contains("abcdefghi\n[Missing 3 bytes]\nend", result);
		Assert.Contains("Reverse direction:\nreply", result.Replace("\r\n", "\n"));
	}

	[Fact]
	public void FollowTcp_SeparatesConnectionsWhenNewSynAppears()
	{
		var syn1 = Packet(1, true, false, 10, 0x02, "");
		var data1 = Packet(2, true, false, 11, 0x10, "old");
		var syn2 = Packet(3, true, false, 100, 0x02, "");
		var data2 = Packet(4, true, false, 101, 0x10, "new");
		string result = PacketAnalysis.FollowConversation(new[] { syn1, data1, syn2, data2 }, data2);
		Assert.Contains("new", result);
		Assert.DoesNotContain("old", result);
	}

	[Fact]
	public void FollowTcp_HandlesOverlapAcrossSequenceWrap()
	{
		var first = Packet(1, true, false, 0xfffffffe, 0x10, "abcd");
		var overlap = Packet(2, true, false, 0, 0x10, "cdef");
		string result = PacketAnalysis.FollowConversation(new[] { first, overlap }, first);
		Assert.Contains("abcdef", result);
	}

	[Fact]
	public void Follow_RejectsOversizedConversationsExplicitly()
	{
		var packet = Packet(1, false, false, 0, 0, "");
		packet.Capture = new CaptureRecord(new byte[16 * 1024 * 1024 + 1], LinkLayers.Ethernet, DateTimeOffset.UnixEpoch, 16 * 1024 * 1024 + 1);
		var exception = Assert.Throws<InvalidOperationException>(() => PacketAnalysis.FollowConversation(new[] { packet }, packet));
		Assert.Contains("16 MiB", exception.Message);
	}

	[Fact]
	public void FollowUdp_PreservesDatagramBoundariesAndDirections()
	{
		var first = Packet(1, false, false, 0, 0, "question");
		var second = Packet(2, false, true, 0, 0, "answer");
		string result = PacketAnalysis.FollowConversation(new[] { first, second }, first);
		Assert.Contains("Packet 1 (selected direction):", result);
		Assert.Contains("Packet 2 (reverse direction):", result);
		Assert.Contains("question", result);
		Assert.Contains("answer", result);
	}
}
