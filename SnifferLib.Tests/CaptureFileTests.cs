using System;
using System.IO;
using PacketDotNet;
using Xunit;

namespace SnifferLib.Tests;

public class CaptureFileTests
{
	[Theory]
	[InlineData(".pcap")]
	[InlineData(".pcapng")]
	public void RoundTrip_PreservesPacketTimestampLengthsAndData(string extension)
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);
		var record = new CaptureRecord([1, 2, 3], LinkLayers.Ethernet,
			DateTimeOffset.FromUnixTimeSeconds(1_700_000_000).AddTicks(1234567), 12, 89);
		try
		{
			CaptureFile.Write(path, [record]);
			var result = Assert.Single(CaptureFile.Read(path));
			Assert.Equal(record.Data, result.Data);
			Assert.Equal(record.LinkLayer, result.LinkLayer);
			Assert.Equal(record.Timestamp, result.Timestamp);
			Assert.Equal(record.TimestampNanosecondRemainder, result.TimestampNanosecondRemainder);
			Assert.Equal(record.OriginalLength, result.OriginalLength);
		}
		finally { File.Delete(path); }
	}

	[Fact]
	public void PcapNg_MultipleInterfacesRoundTrip()
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcapng");
		var first = new CaptureRecord([1, 2, 3, 4], LinkLayers.Ethernet, DateTimeOffset.UnixEpoch, 4);
		var second = new CaptureRecord([5], (LinkLayers)101, DateTimeOffset.UnixEpoch.AddSeconds(1), 1);
		try
		{
			CaptureFile.Write(path, [first, second]);
			var result = CaptureFile.Read(path);
			Assert.Equal(2, result.Count);
			Assert.Equal(first.LinkLayer, result[0].LinkLayer);
			Assert.Equal(second.LinkLayer, result[1].LinkLayer);
			Assert.Equal(second.Data, result[1].Data);
		}
		finally { File.Delete(path); }
	}

	[Fact]
	public void Pcap_MixedInterfacesDoesNotOverwriteExistingFile()
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcap");
		var first = new CaptureRecord([1], LinkLayers.Ethernet, DateTimeOffset.UnixEpoch, 1);
		var second = new CaptureRecord([2], (LinkLayers)101, DateTimeOffset.UnixEpoch, 1);
		try
		{
			File.WriteAllText(path, "existing");
			Assert.Throws<NotSupportedException>(() => CaptureFile.Write(path, [first, second]));
			Assert.Equal("existing", File.ReadAllText(path));
		}
		finally { File.Delete(path); }
	}

	[Fact]
	public void Read_BigEndianPcap_HandlesMicroseconds()
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcap");
		try
		{
			File.WriteAllBytes(path,
			[
				0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0xff, 0xff, 0, 0, 0, 1,
				0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 2, 0, 0, 0, 3, 7, 8
			]);
			var packet = Assert.Single(CaptureFile.Read(path));
			Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(1).AddTicks(100), packet.Timestamp);
			Assert.Equal(3, packet.OriginalLength);
			Assert.Equal(new byte[] { 7, 8 }, packet.Data);
		}
		finally { File.Delete(path); }
	}

	[Fact]
	public void Read_BigEndianPcapNg_UsesInterfaceTimestampResolution()
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcapng");
		try
		{
			File.WriteAllBytes(path,
			[
				10, 13, 13, 10, 0, 0, 0, 28, 0x1a, 0x2b, 0x3c, 0x4d,
				0, 1, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 28,
				0, 0, 0, 1, 0, 0, 0, 20, 0, 1, 0, 0, 0, 0, 255, 255, 0, 0, 0, 20,
				0, 0, 0, 6, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 15, 66, 64, 0, 0, 0, 1, 0, 0, 0, 2, 7, 0, 0, 0, 0, 0, 0, 36
			]);
			var packet = Assert.Single(CaptureFile.Read(path));
			Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(1), packet.Timestamp);
			Assert.Equal(LinkLayers.Ethernet, packet.LinkLayer);
			Assert.Equal(2, packet.OriginalLength);
			Assert.Equal(new byte[] { 7 }, packet.Data);
		}
		finally { File.Delete(path); }
	}

	[Fact]
	public void Read_TruncatedFile_ReportsError()
	{
		string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".pcap");
		try
		{
			File.WriteAllBytes(path, [0xd4, 0xc3, 0xb2, 0xa1, 0]);
			Assert.Throws<InvalidDataException>(() => CaptureFile.Read(path));
		}
		finally { File.Delete(path); }
	}
}
