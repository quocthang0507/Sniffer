using System;
using System.Text;

namespace SnifferLib
{
	public class PacketBuff
	{
		private Lazy<string> buffer;
		private Lazy<string> content;

		public string Buffer
		{
			get => buffer.Value;
			set => buffer = new Lazy<string>(() => value);
		}

		public string Content
		{
			get => content.Value;
			set => content = new Lazy<string>(() => value);
		}

		public PacketBuff(string buffer, string text)
		{
			this.buffer = new Lazy<string>(() => buffer);
			content = new Lazy<string>(() => text);
		}

		public PacketBuff(byte[] bytes)
		{
			ArgumentNullException.ThrowIfNull(bytes);
			buffer = new Lazy<string>(() => FormatHex(bytes));
			content = new Lazy<string>(() => FormatAscii(bytes));
		}

		private static string FormatHex(byte[] bytes)
		{
			StringBuilder builder = new StringBuilder();
			for (int i = 0; i < bytes.Length; i++)
			{
				if (i % 16 == 0)
					builder.Append(i.ToString("x4")).Append("  ");
				builder.Append(bytes[i].ToString("x2")).Append("  ");
				if ((i + 1) % 16 == 0)
					builder.Append('\n');
			}
			return builder.ToString();
		}

		private static string FormatAscii(byte[] bytes)
		{
			StringBuilder builder = new StringBuilder(bytes.Length + bytes.Length / 16);
			for (int i = 0; i < bytes.Length; i++)
			{
				builder.Append(bytes[i] is >= 32 and <= 126 ? (char)bytes[i] : '.');
				if ((i + 1) % 16 == 0)
					builder.Append('\n');
			}
			return builder.ToString();
		}
	}
}
