using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SnifferLib
{

    public class SnifferClass
    {
        private PacketDevice selectedDevice;
        private IList<LivePacketDevice> devices;
        private Stopwatch stopwatch;
        public List<PacketInfo> packets { get; set; }

        /// <summary>
        /// Gets list of interfaces in computer
        /// </summary>
        /// <returns></returns>
        public List<string> GetInterfaces()
        {
            devices = LivePacketDevice.AllLocalMachine;
            List<string> result = new List<string>();
            foreach (var device in devices)
            {
                string name = device.Description;
                string[] array = name.Split('\'');
                result.Add(array[1]);
            }
            return result;
        }

        /// <summary>
        /// Gets the interface by index
        /// </summary>
        /// <param name="index"></param>
        public void GetInterface(int index)
        {
            selectedDevice = devices[index];
        }

        /// <summary>
        /// Gets the name of selected interface
        /// </summary>
        /// <returns></returns>
        public string GetNameInterface()
        {
            return selectedDevice.Description.Split('\'')[1];
        }

        public void Start()
        {
            if (devices.Count == 0)
            {
                throw new AggregateException("No interfaces found! Make sure WinPcap is installed.");
            }
            packets = new List<PacketInfo>();
            stopwatch = new Stopwatch();
            stopwatch.Start();
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // 2^16byte, 64kb, max size của gói tin
                                    PacketDeviceOpenAttributes.Promiscuous, // Chế độ bắt tất cả gói tin đang truyền trên mạng
                                    1000))                                  // Thời gian chờ tối đa
            {
                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        private void PacketHandler(Packet packet)
        {
            PacketInfo info = new PacketInfo();
            info.ID = packets.Count + 1; // ban đầu là 0 id =1
            info.Time = stopwatch.Elapsed.TotalSeconds;
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp; //TCP với UDP ra thông tin như nhau
            if (udp != null)
            {
                info.Source = ip.Source.ToString();
                info.Destination = ip.Destination.ToString();
                info.Protocol = packet.Ethernet.EtherType.ToString();
                info.Length = packet.Length;
                UTF8Encoding encoding = new UTF8Encoding();
                info.Buffer = new PacketBuff(BitConverter.ToString(packet.Buffer), encoding.GetString(packet.Buffer));// doi tuong
                info.Info = "";
            }
            packets.Add(info);
        }

    }
}
