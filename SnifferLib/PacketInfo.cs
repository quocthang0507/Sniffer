using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
		public float Time { get; set; }
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
		/// Thông tin
		/// </summary>
		public string Info { get; set; }

		public PacketInfo(int iD, float time, string source, string destination, string protocol, string info)
		{
			ID = iD;
			Time = time;
			Source = source;
			Destination = destination;
			Protocol = protocol;
			Info = info;
		}
	}
}
