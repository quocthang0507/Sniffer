using System.Net;

namespace SnifferLib
{
	public class PacketInfo
	{
		/// <summary>
		/// STT
		/// </summary>
		public int ID { get; set; }
		/// <summary>
		/// Thời gian
		/// </summary>
		public double Time { get; set; }
		/// <summary>
		/// IP nguồn
		/// </summary>
		public string Source { get; set; } = string.Empty;
		/// <summary>
		/// Ip đích
		/// </summary>
		public string Destination { get; set; } = string.Empty;
		/// <summary>
		/// Giao thức
		/// </summary>
		public string Protocol { get; set; } = string.Empty;
		/// <summary>
		/// Nội dung gói tin
		/// </summary>
		public PacketBuff Buffer { get; set; } = new PacketBuff(string.Empty, string.Empty);
		/// <summary>
		/// Chiều dài
		/// </summary>
		public int Length { get; set; }
		/// <summary>
		/// Thông tin
		/// </summary>
		public string Info { get; set; } = string.Empty;
		/// <summary>
		/// Thông tin các tầng trong gói tin
		/// </summary>
		public PacketLayer Layers { get; set; } = new PacketLayer();
		public CaptureRecord? Capture { get; set; }
		public IPAddress? SourceAddress { get; set; }
		public IPAddress? DestinationAddress { get; set; }
		public ushort? SourcePort { get; set; }
		public ushort? DestinationPort { get; set; }
		public string? TransportProtocol { get; set; }

		public PacketInfo()
		{

		}

		public PacketInfo(int iD, double time, string source, string destination, string protocol, PacketBuff buffer, int length, string info, PacketLayer layers)
		{
			ID = iD;
			Time = time;
			Source = source;
			Destination = destination;
			Protocol = protocol;
			Buffer = buffer;
			Length = length;
			Info = info;
			Layers = layers;
		}
	}
}
