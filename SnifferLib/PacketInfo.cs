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
		public string Source { get; set; }
		/// <summary>
		/// Ip đích
		/// </summary>
		public string Destination { get; set; }
		/// <summary>
		/// Giao thức
		/// </summary>
		public string Protocol { get; set; }
		/// <summary>
		/// Nội dung gói tin
		/// </summary>
		public PacketBuff Buffer { get; set; }
		/// <summary>
		/// Chiều dài
		/// </summary>
		public int Length { get; set; }
		/// <summary>
		/// Thông tin
		/// </summary>
		public string Info { get; set; }
		/// <summary>
		/// Thông tin các tầng trong gói tin
		/// </summary>
		public PacketLayer Layers { get; set; }

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
