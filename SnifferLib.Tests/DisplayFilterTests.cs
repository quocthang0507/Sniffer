using System;
using System.Net;
using Xunit;

namespace SnifferLib.Tests;

public class DisplayFilterTests
{
	private static PacketInfo DnsPacket() => new PacketInfo
	{
		Protocol = "DNS",
		TransportProtocol = "UDP",
		SourceAddress = IPAddress.Parse("192.0.2.1"),
		DestinationAddress = IPAddress.Parse("2001:db8::1"),
		SourcePort = 12345,
		DestinationPort = 53,
		Layers = new PacketLayer { UDPInfo = "UDP", DNSInfo = "DNS" }
	};

	[Theory]
	[InlineData("udp && dns")]
	[InlineData("udp.port == 53 && ip.addr == 192.0.2.1")]
	[InlineData("tcp || (dns && ip.addr == 2001:db8::1)")]
	[InlineData("tcp || udp && dns")]
	public void Parse_MatchesProtocolLayersAndExpressions(string expression)
	{
		Assert.True(DisplayFilter.Parse(expression)(DnsPacket()));
	}

	[Theory]
	[InlineData("tcp")]
	[InlineData("tcp.port == 53")]
	[InlineData("(tcp || udp) && ip.addr == 192.0.2.2")]
	public void Parse_DoesNotMatchOtherTraffic(string expression)
	{
		Assert.False(DisplayFilter.Parse(expression)(DnsPacket()));
	}

	[Theory]
	[InlineData("udp &&")]
	[InlineData("ip.addr == nope")]
	[InlineData("tcp.port == 65536")]
	[InlineData("(udp")]
	[InlineData("udp | tcp")]
	[InlineData("unknown")]
	public void Parse_RejectsInvalidExpressions(string expression)
	{
		Assert.Throws<FormatException>(() => DisplayFilter.Parse(expression));
	}
}
