using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnifferLib
{
	public class PacketLayer
	{
		/// <summary>
		/// Thông tin tầng HTTP trong gói tin
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

		public PacketLayer(string hTTPInfo, string tCPInfo, string uDPInfo, string iPInfo, string ethernetInfo)
		{
			HTTPInfo = hTTPInfo;
			TCPInfo = tCPInfo;
			UDPInfo = uDPInfo;
			IPInfo = iPInfo;
			EthernetInfo = ethernetInfo;
		}
	}
}
