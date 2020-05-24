namespace SnifferLib
{
    public class PacketBuff
    {
        public string Buffer { get; set; }
        public string UTF8 { get; set; }

        public PacketBuff(string buffer, string text)
        {
            Buffer = buffer;
            UTF8 = text;
        }
    }
}
