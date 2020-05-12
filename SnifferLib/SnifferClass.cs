using PcapDotNet.Core;
using System.Collections.Generic;

namespace SnifferLib
{
    public class SnifferClass
    {
        private PacketDevice selectedDevice;
        private IList<LivePacketDevice> devices;

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
                string[] array=  name.Split('\'');
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
    }
}
