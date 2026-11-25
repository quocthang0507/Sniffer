using PacketDotNet;
using SnifferLib;
using System;
using System.Text;
using Xunit;

namespace SnifferLib.Tests;

public class PacketParserTests
{
	[Fact]
	public void Parse_UnknownEtherType_PreservesEthernetAddresses()
	{
		byte[] frame =
		[
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x88, 0xB5
		];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0.25);

		Assert.Equal("EtherType 0x88B5", packet.Protocol);
		Assert.Equal("00-11-22-33-44-55", packet.Source);
		Assert.Equal("66-77-88-99-AA-BB", packet.Destination);
		Assert.Equal(frame.Length, packet.Length);
	}

	[Fact]
	public void Parse_TruncatedEthernetFrame_ReturnsMalformedPacket()
	{
		byte[] frame = new byte[13];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("Malformed Ethernet", packet.Protocol);
		Assert.Contains("shorter than an Ethernet header", packet.Info);
	}

	[Fact]
	public void Parse_ArpResponse_UsesProtocolAddressesAndSenderMac()
	{
		byte[] frame =
		[
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x08, 0x06,
			0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0xC0, 0x00, 0x02, 0x01,
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0xC0, 0x00, 0x02, 0x02
		];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("ARP", packet.Protocol);
		Assert.Equal("192.0.2.1", packet.Source);
		Assert.Equal("192.0.2.2", packet.Destination);
		Assert.Contains("00-11-22-33-44-55", packet.Info);
	}

	[Fact]
	public void Parse_UdpOverIpv4_ExtractsAddressesAndPorts()
	{
		byte[] frame =
		[
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x08, 0x00,
			0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
			0xC6, 0x33, 0x64, 0x02,
			0x00, 0x35, 0x1F, 0x90, 0x00, 0x08, 0x00, 0x00
		];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("UDP", packet.Protocol);
		Assert.Equal("192.0.2.1", packet.Source);
		Assert.Equal("198.51.100.2", packet.Destination);
		Assert.Contains("53", packet.Info);
		Assert.Contains("8080", packet.Info);
	}

	[Fact]
	public void Parse_UdpOverIpv6_ExtractsAddressesAndPorts()
	{
		byte[] frame =
		[
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x86, 0xDD,
			0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
			0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			0x00, 0x35, 0x1F, 0x90, 0x00, 0x08, 0x00, 0x00
		];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("UDP", packet.Protocol);
		Assert.Equal("2001:db8::1", packet.Source);
		Assert.Equal("2001:db8::2", packet.Destination);
		Assert.Contains("53", packet.Info);
		Assert.Contains("8080", packet.Info);
	}

	[Fact]
	public void Parse_TruncatedIpv4Header_ReturnsMalformedPacket()
	{
		byte[] frame =
		[
			0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			0x08, 0x00, 0x45, 0x00, 0x00, 0x14
		];

		PacketInfo packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.StartsWith("Malformed", packet.Protocol);
	}

	[Fact]
	public void Parse_DnsQuery_PreservesUdpLayerAndShowsQuestion()
	{
		byte[] frame =
		[
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
			0x45, 0, 0, 53, 0, 0, 0, 0, 64, 17, 0, 0,
			192, 0, 2, 1, 192, 0, 2, 2,
			0x30, 0x39, 0, 53, 0, 33, 0, 0,
			0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
			3, (byte)'w', (byte)'w', (byte)'w', 3, (byte)'c', (byte)'o', (byte)'m',
			0, 0, 1, 0, 1
		];

		var packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("DNS", packet.Protocol);
		Assert.Contains("www.com", packet.Info);
		Assert.NotNull(packet.Layers.UDPInfo);
		Assert.NotNull(packet.Layers.DNSInfo);
		Assert.Equal((ushort)53, packet.DestinationPort);
		Assert.StartsWith("0000  ", packet.Buffer.Buffer);
		Assert.StartsWith("..............E.", packet.Buffer.Content);
	}

	[Fact]
	public void Parse_HttpRequest_RetainsTcpLayer()
	{
		byte[] header =
		[
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00,
			0x45, 0, 0, 67, 0, 0, 0, 0, 64, 6, 0, 0,
			192, 0, 2, 1, 192, 0, 2, 2,
			0x30, 0x39, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0,
			0x50, 0x18, 0x10, 0, 0, 0, 0, 0
		];
		byte[] payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
		byte[] frame = new byte[header.Length + payload.Length];
		header.CopyTo(frame, 0);
		payload.CopyTo(frame, header.Length);

		var packet = PacketParser.Parse(frame, LinkLayers.Ethernet, 1, 0);

		Assert.Equal("HTTP", packet.Protocol);
		Assert.Equal("GET / HTTP/1.1", packet.Info);
		Assert.NotNull(packet.Layers.TCPInfo);
		Assert.Contains("Host: x", packet.Layers.HTTPInfo);
		Assert.True(DisplayFilter.Parse("http && tcp.port == 80")(packet));
	}

	[Fact]
	public void Parse_TruncatedTransportAndArpFrames_DoesNotThrow()
	{
		byte[][] frames =
		[
			[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0,
			 0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
			 0x30, 0x39, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0x10, 0, 0, 0, 0, 0],
			[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 6,
			 0, 1, 8, 0, 6, 4, 0, 1, 0, 1, 2, 3, 4, 5, 192, 0, 2, 1,
			 0, 0, 0, 0, 0, 0, 192, 0, 2, 2]
		];
		foreach (var frame in frames)
		{
			for (int length = 0; length < frame.Length; length++)
			{
				byte[] truncated = frame[..length];
				Exception? exception = Record.Exception(() => PacketParser.Parse(truncated, LinkLayers.Ethernet, 1, 0));
				Assert.True(exception is null, $"Length {length}: {exception}");
			}
		}
	}
}
