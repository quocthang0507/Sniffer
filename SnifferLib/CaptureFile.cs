using PacketDotNet;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SnifferLib
{
	public sealed record CaptureRecord(byte[] Data, LinkLayers LinkLayer, DateTimeOffset Timestamp,
		int OriginalLength, int TimestampNanosecondRemainder = 0);

	public static class CaptureFile
	{
		private const int MaxBlockSize = 64 * 1024 * 1024;
		private const uint SectionHeader = 0x0A0D0D0A;
		private sealed record CaptureInterface(LinkLayers LinkLayer, decimal UnitsPerSecond, long OffsetSeconds);

		public static IReadOnlyList<CaptureRecord> Read(string path)
		{
			using var stream = File.OpenRead(path);
			Span<byte> magic = stackalloc byte[4];
			ReadExactly(stream, magic);
			if (magic.SequenceEqual(new byte[] { 0x0a, 0x0d, 0x0d, 0x0a }))
			{
				stream.Position = 0;
				return ReadPcapNg(stream);
			}
			bool little;
			bool nanoseconds;
			if (magic.SequenceEqual(new byte[] { 0xd4, 0xc3, 0xb2, 0xa1 })) { little = true; nanoseconds = false; }
			else if (magic.SequenceEqual(new byte[] { 0xa1, 0xb2, 0xc3, 0xd4 })) { little = false; nanoseconds = false; }
			else if (magic.SequenceEqual(new byte[] { 0x4d, 0x3c, 0xb2, 0xa1 })) { little = true; nanoseconds = true; }
			else if (magic.SequenceEqual(new byte[] { 0xa1, 0xb2, 0x3c, 0x4d })) { little = false; nanoseconds = true; }
			else throw new InvalidDataException("Not a supported PCAP or PCAPNG file.");
			byte[] header = ReadBytes(stream, 20);
			if (U16(header, 0, little) != 2 || U16(header, 2, little) != 4)
				throw new InvalidDataException("Unsupported PCAP version.");
			uint link = U32(header, 16, little);
			if (link > ushort.MaxValue)
				throw new NotSupportedException("PCAP link-layer metadata is not supported.");
			var result = new List<CaptureRecord>();
			while (stream.Position < stream.Length)
			{
				byte[] packetHeader = ReadBytes(stream, 16);
				uint seconds = U32(packetHeader, 0, little);
				uint fraction = U32(packetHeader, 4, little);
				uint captured = U32(packetHeader, 8, little);
				uint original = U32(packetHeader, 12, little);
				uint units = nanoseconds ? 1_000_000_000u : 1_000_000u;
				if (fraction >= units)
					throw new InvalidDataException("Invalid PCAP timestamp.");
				ValidateLengths(captured, original, stream.Length - stream.Position);
				var timestamp = TimestampFromSeconds(seconds + (decimal)fraction / units, out int remainder);
				result.Add(new CaptureRecord(ReadBytes(stream, (int)captured), (LinkLayers)link, timestamp, (int)original, remainder));
			}
			return result;
		}

		private static IReadOnlyList<CaptureRecord> ReadPcapNg(Stream stream)
		{
			var packets = new List<CaptureRecord>();
			var interfaces = new List<CaptureInterface>();
			bool little = true;
			bool hasSection = false;
			while (stream.Position < stream.Length)
			{
				byte[] prefix = ReadBytes(stream, 8);
				bool section = U32(prefix, 0, true) == SectionHeader;
				byte[] body;
				uint type;
				uint size;
				if (section)
				{
					byte[] bom = ReadBytes(stream, 4);
					if (bom.SequenceEqual(new byte[] { 0x4d, 0x3c, 0x2b, 0x1a })) little = true;
					else if (bom.SequenceEqual(new byte[] { 0x1a, 0x2b, 0x3c, 0x4d })) little = false;
					else throw new InvalidDataException("Invalid PCAPNG byte order.");
					size = U32(prefix, 4, little);
					ValidateBlockSize(size, 28, stream.Length - stream.Position + 12);
					body = ReadBytes(stream, checked((int)size - 12));
					if (U16(body, 0, little) != 1)
						throw new NotSupportedException("Unsupported PCAPNG version.");
					interfaces.Clear();
					hasSection = true;
					type = SectionHeader;
				}
				else
				{
					if (!hasSection)
						throw new InvalidDataException("PCAPNG section header is missing.");
					type = U32(prefix, 0, little);
					size = U32(prefix, 4, little);
					ValidateBlockSize(size, 12, stream.Length - stream.Position + 8);
					body = ReadBytes(stream, checked((int)size - 8));
				}
				if (U32(body, body.Length - 4, little) != size)
					throw new InvalidDataException("PCAPNG block lengths do not match.");
				if (type == 1)
				{
					if (body.Length < 12)
						throw new InvalidDataException("Truncated PCAPNG interface block.");
					decimal units = 1_000_000;
					long offset = 0;
					int option = 8;
					while (option < body.Length - 4)
					{
						if (option + 4 > body.Length - 4)
							throw new InvalidDataException("Truncated PCAPNG option.");
						ushort code = U16(body, option, little);
						ushort length = U16(body, option + 2, little);
						option += 4;
						int padded = (length + 3) & ~3;
						if (option + padded > body.Length - 4)
							throw new InvalidDataException("Truncated PCAPNG option value.");
						if (code == 0)
						{
							if (length != 0) throw new InvalidDataException("Invalid PCAPNG end option.");
							break;
						}
						if (code == 9)
						{
							if (length != 1) throw new InvalidDataException("Invalid PCAPNG timestamp resolution.");
							byte resolution = body[option];
							int exponent = resolution & 0x7f;
							int radix = (resolution & 0x80) == 0 ? 10 : 2;
							units = 1;
							try { for (int i = 0; i < exponent; i++) units = checked(units * radix); }
							catch (OverflowException) { throw new NotSupportedException("PCAPNG timestamp resolution is too fine."); }
						}
						else if (code == 14)
						{
							if (length != 8) throw new InvalidDataException("Invalid PCAPNG timestamp offset.");
							offset = unchecked((long)U64(body, option, little));
						}
						option += padded;
					}
					interfaces.Add(new CaptureInterface((LinkLayers)U16(body, 0, little), units, offset));
				}
				else if (type is 6 or 2)
				{
					if (body.Length < 24)
						throw new InvalidDataException("Truncated PCAPNG packet block.");
					uint interfaceId = type == 6 ? U32(body, 0, little) : U16(body, 0, little);
					if (interfaceId >= interfaces.Count)
						throw new InvalidDataException("PCAPNG packet refers to an unknown interface.");
					ulong rawTime = ((ulong)U32(body, 4, little) << 32) | U32(body, 8, little);
					uint captured = U32(body, 12, little);
					uint original = U32(body, 16, little);
					ValidateLengths(captured, original, body.Length - 24);
					int padded = checked(((int)captured + 3) & ~3);
					if (padded > body.Length - 24)
						throw new InvalidDataException("Truncated PCAPNG packet padding.");
					var adapter = interfaces[(int)interfaceId];
					var timestamp = TimestampFromSeconds(adapter.OffsetSeconds + rawTime / adapter.UnitsPerSecond, out int remainder);
					var data = new byte[(int)captured];
					Array.Copy(body, 20, data, 0, data.Length);
					packets.Add(new CaptureRecord(data, adapter.LinkLayer, timestamp, (int)original, remainder));
				}
				else if (type == 3)
				{
					throw new NotSupportedException("PCAPNG simple packet blocks have no timestamp and are not supported.");
				}
			}
			return packets;
		}

		public static void Write(string path, IReadOnlyList<CaptureRecord> packets)
		{
			ArgumentNullException.ThrowIfNull(packets);
			string extension = Path.GetExtension(path);
			bool pcapng = extension.Equals(".pcapng", StringComparison.OrdinalIgnoreCase);
			if (!pcapng && !extension.Equals(".pcap", StringComparison.OrdinalIgnoreCase))
				throw new ArgumentException("Choose a .pcap or .pcapng file.", nameof(path));
			string fullPath = Path.GetFullPath(path);
			string temporary = Path.Combine(Path.GetDirectoryName(fullPath)!, $".{Guid.NewGuid():N}.tmp");
			try
			{
				using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
				using (var writer = new BinaryWriter(stream))
				{
					if (pcapng) WritePcapNg(writer, packets);
					else WritePcap(writer, packets);
				}
				File.Move(temporary, fullPath, true);
			}
			finally
			{
				if (File.Exists(temporary))
					File.Delete(temporary);
			}
		}

		private static void WritePcap(BinaryWriter writer, IReadOnlyList<CaptureRecord> packets)
		{
			var link = packets.Count == 0 ? LinkLayers.Ethernet : packets[0].LinkLayer;
			if (packets.Any(packet => packet.LinkLayer != link))
				throw new NotSupportedException("PCAP cannot store multiple link-layer types; use PCAPNG.");
			if ((long)link < 0 || (long)link > ushort.MaxValue)
				throw new NotSupportedException("Unsupported PCAP link-layer type.");
			writer.Write(0xa1b23c4du);
			writer.Write((ushort)2); writer.Write((ushort)4);
			writer.Write(0); writer.Write(0); writer.Write((uint)MaxBlockSize); writer.Write((uint)link);
			foreach (var packet in packets)
			{
				ValidateRecord(packet);
				decimal seconds = SecondsFromTimestamp(packet);
				if (seconds < 0 || seconds >= (decimal)uint.MaxValue + 1)
					throw new NotSupportedException("Timestamp is outside the PCAP range; use PCAPNG.");
				uint whole = (uint)decimal.Truncate(seconds);
				writer.Write(whole);
				writer.Write((uint)((seconds - whole) * 1_000_000_000m));
				writer.Write((uint)packet.Data.Length);
				writer.Write((uint)packet.OriginalLength);
				writer.Write(packet.Data);
			}
		}

		private static void WritePcapNg(BinaryWriter writer, IReadOnlyList<CaptureRecord> packets)
		{
			writer.Write(SectionHeader); writer.Write(28u); writer.Write(0x1a2b3c4du);
			writer.Write((ushort)1); writer.Write((ushort)0); writer.Write(-1L); writer.Write(28u);
			var interfaces = new Dictionary<LinkLayers, uint>();
			foreach (var packet in packets)
			{
				ValidateRecord(packet);
				if (packet.Data.Length > MaxBlockSize - 32)
					throw new NotSupportedException("Packet is too large for a PCAPNG block.");
				if (!interfaces.TryGetValue(packet.LinkLayer, out uint id))
				{
					if ((long)packet.LinkLayer < 0 || (long)packet.LinkLayer > ushort.MaxValue)
						throw new NotSupportedException("Unsupported PCAPNG link-layer type.");
					id = (uint)interfaces.Count;
					interfaces.Add(packet.LinkLayer, id);
					writer.Write(1u); writer.Write(32u); writer.Write((ushort)packet.LinkLayer);
					writer.Write((ushort)0); writer.Write((uint)MaxBlockSize);
					writer.Write((ushort)9); writer.Write((ushort)1); writer.Write((byte)9);
					writer.Write(new byte[3]); writer.Write(0u); writer.Write(32u);
				}
				decimal nanos = SecondsFromTimestamp(packet) * 1_000_000_000m;
				if (nanos < 0 || nanos > ulong.MaxValue)
					throw new NotSupportedException("Timestamp is outside the supported PCAPNG range.");
				ulong time = (ulong)nanos;
				int padding = (4 - packet.Data.Length % 4) % 4;
				uint blockLength = checked((uint)(32 + packet.Data.Length + padding));
				writer.Write(6u); writer.Write(blockLength); writer.Write(id);
				writer.Write((uint)(time >> 32)); writer.Write((uint)time);
				writer.Write((uint)packet.Data.Length); writer.Write((uint)packet.OriginalLength);
				writer.Write(packet.Data); writer.Write(new byte[padding]); writer.Write(blockLength);
			}
		}

		private static void ValidateRecord(CaptureRecord packet)
		{
			ArgumentNullException.ThrowIfNull(packet);
			ArgumentNullException.ThrowIfNull(packet.Data);
			ValidateLengths((uint)packet.Data.Length, (uint)packet.OriginalLength, packet.Data.Length);
			if (packet.OriginalLength < 0 || packet.TimestampNanosecondRemainder is < 0 or > 99)
				throw new ArgumentException("Invalid packet length or timestamp precision.");
		}

		private static decimal SecondsFromTimestamp(CaptureRecord packet) =>
			(packet.Timestamp.ToUniversalTime().Ticks - DateTimeOffset.UnixEpoch.Ticks) / (decimal)TimeSpan.TicksPerSecond +
			packet.TimestampNanosecondRemainder / 1_000_000_000m;

		private static DateTimeOffset TimestampFromSeconds(decimal seconds, out int remainder)
		{
			try
			{
				decimal nanos = seconds * 1_000_000_000m;
				if (nanos != decimal.Truncate(nanos))
					throw new NotSupportedException("Sub-nanosecond PCAPNG timestamps are not supported.");
				decimal ticks = decimal.Floor(nanos / 100);
				remainder = (int)(nanos - ticks * 100);
				return DateTimeOffset.UnixEpoch.AddTicks(checked((long)ticks));
			}
			catch (Exception exception) when (exception is OverflowException or ArgumentOutOfRangeException)
			{
				throw new InvalidDataException("Capture timestamp is out of range.", exception);
			}
		}

		private static void ValidateLengths(uint captured, uint original, long available)
		{
			if (captured > MaxBlockSize || captured > original || original > int.MaxValue || captured > available)
				throw new InvalidDataException("Invalid or truncated capture packet length.");
		}

		private static void ValidateBlockSize(uint size, uint minimum, long available)
		{
			if (size < minimum || size > MaxBlockSize || size % 4 != 0 || size > available)
				throw new InvalidDataException("Invalid or truncated PCAPNG block.");
		}

		private static byte[] ReadBytes(Stream stream, int count)
		{
			var bytes = new byte[count];
			ReadExactly(stream, bytes);
			return bytes;
		}

		private static void ReadExactly(Stream stream, Span<byte> bytes)
		{
			try { stream.ReadExactly(bytes); }
			catch (EndOfStreamException exception) { throw new InvalidDataException("Capture file is truncated.", exception); }
		}

		private static ushort U16(byte[] bytes, int offset, bool little) =>
			little ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset)) : BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset));
		private static uint U32(byte[] bytes, int offset, bool little) =>
			little ? BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset)) : BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset));
		private static ulong U64(byte[] bytes, int offset, bool little) =>
			little ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset)) : BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(offset));
	}
}
