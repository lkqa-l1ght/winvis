using System.Text;

namespace CIDReader.Parsers
{
    static class TlvParser              // Phân tách thông tin cho dữ liệu đọc được từ DG13
    {
        private static readonly string[] Dg13Labels = new string[]
        {
            "Số CCCD",
            "Họ và tên",
            "Ngày sinh",
            "Giới tính",
            "Quốc tịch",
            "Dân tộc",
            "Tôn giáo",
            "Quê quán",
            "Nơi thường trú",
            "Đặc điểm nhận dạng",
            "Ngày cấp",
            "Ngày hết hạn",
            "Họ tên cha",
            "Họ tên mẹ",
            "Tag C"
        };

        private static int _textIndex = 0;

        public static void ExtractDG13(byte[] data)             // Hàm in dữ liệu
        {
            _textIndex = 0;
            Console.WriteLine("\n  ╔══════════════════ THÔNG TIN TỪ DG13 ══════════════════╗");
            ParseTLV(data, 0, data.Length);
            Console.WriteLine("  ╚═══════════════════════════════════════════════════════╝");
        }

        private static void ParseTLV(byte[] data, int start, int end)
        {
            int i = start;
            while (i < end)
            {
                try
                {
                    int tag = data[i++];
                    bool isConstructed = (tag & 0x20) != 0;

                    if ((tag & 0x1F) == 0x1F)
                    {
                        tag = (tag << 8) | data[i++];
                    }

                    if (i >= end) break;
                    int len = data[i++];
                    if ((len & 0x80) != 0)
                    {
                        int lenBytes = len & 0x7F;
                        len = 0;
                        for (int j = 0; j < lenBytes; j++)
                        {
                            if (i >= end) break;
                            len = (len << 8) | data[i++];
                        }
                    }

                    if (i + len > end) break;

                    if (isConstructed)
                    {
                        ParseTLV(data, i, i + len);
                    }
                    else
                    {
                        if (len > 0)
                        {
                            byte[] val = new byte[len];
                            Array.Copy(data, i, val, 0, len);

                            string text = Encoding.UTF8.GetString(val).Replace("\0", "").Trim();

                            if ((tag == 0x0C || tag == 0x13) && val.Any(b => b != 0x00))
                            {
                                string label = _textIndex < Dg13Labels.Length
                                    ? Dg13Labels[_textIndex]
                                    : $"Trường số {_textIndex}";

                                PrintRow(label, text);
                                _textIndex++;
                            }
                        }
                    }
                    i += len;
                }
                catch { break; }
            }
        }

        private static void PrintRow(string label, string value)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  ║ ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label,-18}: ");
            Console.ForegroundColor = ConsoleColor.Yellow;

            var lines = value.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length > 0)
            {
                Console.Write($"{lines[0],-39}");
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(" ║");

                for (int i = 1; i < lines.Length; i++)
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write("  ║ ");
                    Console.Write($"{"",-18}  ");
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write($"{lines[i],-39}");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine(" ║");
                }
            }
        }
    }
}