using PcapDotNet.Core;
using System.Collections.Generic;

namespace SnifferLib
{
    public class SnifferClass
    {
        public static List<string> GetInterfaces()
        {
            var devices=  LivePacketDevice.AllLocalMachine;
            List<string> result = new List<string>();
            foreach (var device in devices)
            {
                string name = device.Description;
               string[] array=  name.Split('\'');
                result.Add(array[1]);
            }
            return result;
        }


    }
}
