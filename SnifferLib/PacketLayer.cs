namespace SnifferLib
{
	public class PacketLayer
	{
		/// <summary>
		/// Thông tin ICMP trong gói tin
		/// </summary>
		public string ICMPInfo { get; set; }
		/// <summary>
		/// Thông tin HTTP trong gói tin
		/// </summary>
		public string HTTPInfo { get; set; }
		/// <summary>
		/// Thông tin TCP trong gói tin
		/// </summary>
		public string TCPInfo { get; set; }
		/// <summary>
		/// Thông tin UDP trong gói tin
		/// </summary>
		public string UDPInfo { get; set; }
		/// <summary>
		/// Thông tin tầng IP trong gói tin
		/// </summary>
		public string IPInfo { get; set; }
		/// <summary>
		/// Thông tin tầng Ethernet trong gói tin
		/// </summary>
		public string EthernetInfo { get; set; }

		public PacketLayer()
		{

		}
	}
}
