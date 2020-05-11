using PcapDotNet.Core;
using System.Collections.Generic;

namespace SnifferLib
{
    public class SnifferClass
    {
        private PacketDevice selectedDevice;
        private IList<LivePacketDevice> devices;

        public List<string> GetInterfaces()
        {
            devices = LivePacketDevice.AllLocalMachine;
            List<string> result = new List<string>();
            foreach (var device in devices)
            {
                string name = device.Description;
                string[] array=  name.Split('\'');
                result.Add(array[1]);
            }
            return result;
        }
        public void GetInterface(int index)
        {
            selectedDevice = devices[index];
        }

        public string GetNameInterface()
        {
            return selectedDevice.Description.Split('\'')[1];
        }
    }
}
