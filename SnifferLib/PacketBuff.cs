namespace SnifferLib
{
	public class PacketBuff
	{
		public string Buffer { get; set; }
		public string Content { get; set; }

		public PacketBuff(string buffer, string text)
		{
			Buffer = buffer;
			Content = text;
		}
	}
}
