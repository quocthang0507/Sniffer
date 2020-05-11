using PcapDotNet.Core;
using System;
using System.Collections.Generic;

namespace PCap.Net
{
	class Program
	{
		static void Main(string[] args)
		{
			IList<LivePacketDevice> devices = LivePacketDevice.AllLocalMachine;

			Lib pcap = new Lib(LivePacketDevice.AllLocalMachine);

			Console.WriteLine("Chon chuc nang muon xem");
			Console.WriteLine("1. Xem chi tiet interface");
			Console.WriteLine("2. Bat goi tin tu interface");
			Console.Write("Lua chon cua ban: ");

			int index = int.Parse(Console.ReadLine());
			PacketDevice selected;

			switch (index)
			{
				case 1:
					selected = pcap.ChooseDeviceFromList();
					Console.WriteLine(pcap.GetDetail(selected));
					break;
				case 2:
					selected = pcap.ChooseDeviceFromList();
					pcap.SelectedDevice = selected;
					pcap.Sniffer();
					break;
				default:
					break;
			}
			Console.ReadKey();
		}


	}
}
