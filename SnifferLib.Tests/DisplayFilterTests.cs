using System;
using System.Net;
using System.Runtime.ExceptionServices;
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
	[InlineData("udp.srcport == 12345 && udp.dstport >= 53")]
	[InlineData("frame.len >= 0 && frame.number == 0")]
	[InlineData("!tcp && ip.src == 192.0.2.1")]
	[InlineData("udp.port != 80")]
	public void Parse_MatchesProtocolLayersAndExpressions(string expression)
	{
		Assert.True(DisplayFilter.Parse(expression)(DnsPacket()));
		Assert.True(DisplayFilter.TryParse(expression, out var filter, out var error));
		Assert.Null(error);
		Assert.NotNull(filter);
		Assert.True(filter(DnsPacket()));
	}

	[Theory]
	[InlineData("tcp")]
	[InlineData("tcp.port == 53")]
	[InlineData("(tcp || udp) && ip.addr == 192.0.2.2")]
	[InlineData("udp.dstport != 53")]
	[InlineData("frame.len > 0")]
	[InlineData("ipv6.src == 2001:db8::1")]
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
	[InlineData("ip.src == 2001:db8::1")]
	[InlineData("frame.len == -1")]
	[InlineData("udp.port > 65536")]
	[InlineData("!")]
	public void Parse_RejectsInvalidExpressions(string expression)
	{
		Assert.Throws<FormatException>(() => DisplayFilter.Parse(expression));
		Assert.False(DisplayFilter.TryParse(expression, out var filter, out var error));
		Assert.Null(filter);
		Assert.False(string.IsNullOrEmpty(error));
	}

	[Fact]
	public void TryParse_TypingInvalidFilterDoesNotThrowFirstChanceExceptions()
	{
		int thread = Environment.CurrentManagedThreadId;
		int exceptions = 0;
		EventHandler<FirstChanceExceptionEventArgs> handler = (_, args) =>
		{
			if (Environment.CurrentManagedThreadId == thread && args.Exception is FormatException)
				exceptions++;
		};
		AppDomain.CurrentDomain.FirstChanceException += handler;
		try
		{
			foreach (string expression in new[] { "o", "on", "onl", "onli", "onlin", "online", "tcp &&", "(udp" })
			{
				Assert.False(DisplayFilter.TryParse(expression, out var filter, out var error));
				Assert.Null(filter);
				Assert.False(string.IsNullOrEmpty(error));
			}
			Assert.True(DisplayFilter.TryParse("tcp && udp", out var valid, out var validError));
			Assert.NotNull(valid);
			Assert.Null(validError);
		}
		finally
		{
			AppDomain.CurrentDomain.FirstChanceException -= handler;
		}
		Assert.Equal(0, exceptions);
	}
}
