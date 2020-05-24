using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnifferLib
{
	public class PacketInfo
	{
		public int ID { get; set; }
		public float Time { get; set; }
		public string Source { get; set; }
		public string Destination { get; set; }
		public string Protocol { get; set; }
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
