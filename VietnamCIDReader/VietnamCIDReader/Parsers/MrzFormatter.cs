using System.Text;
using CIDReader.Utils;

namespace CIDReader.Parsers
{
    class MrzFormatter
    {
        public static void PrintBeautiful(byte[] dg1Raw)
        {
            string mrz = ExtractCleanMrz(dg1Raw);
            if (string.IsNullOrEmpty(mrz))
            {
                Con.Err("Không thể trích xuất MRZ từ chuỗi DG1 raw.");
                return;
            }

            string docType = "Unknown", issuingState = "", name = "", docNum = "", nationality = "", dob = "", sex = "", expiry = "";

            if (mrz.Length == 88)
            {
                docType = mrz.Substring(0, 2).Replace("<", "");
                issuingState = mrz.Substring(2, 3).Replace("<", "");
                name = FormatName(mrz.Substring(5, 39));

                docNum = mrz.Substring(44, 9).Replace("<", "");
                nationality = mrz.Substring(54, 3).Replace("<", "");
                dob = FormatDate(mrz.Substring(57, 6));
                sex = FormatSex(mrz.Substring(64, 1));
                expiry = FormatDate(mrz.Substring(65, 6));
            }
            else if (mrz.Length == 90)
            {
                docType = mrz.Substring(0, 2).Replace("<", "");
                issuingState = mrz.Substring(2, 3).Replace("<", "");

                if (issuingState == "VNM")
                {
                    docNum = mrz.Substring(5, 12).Replace("<", "");
                }
                else
                {
                    docNum = mrz.Substring(5, 9).Replace("<", "");
                }

                dob = FormatDate(mrz.Substring(30, 6));
                sex = FormatSex(mrz.Substring(37, 1));
                expiry = FormatDate(mrz.Substring(38, 6));
                nationality = mrz.Substring(45, 3).Replace("<", "");

                name = FormatName(mrz.Substring(60, 30));
            }
            else if (mrz.Length == 72)
            {
                docType = mrz.Substring(0, 2).Replace("<", "");
                issuingState = mrz.Substring(2, 3).Replace("<", "");
                name = FormatName(mrz.Substring(5, 31));

                docNum = mrz.Substring(36, 9).Replace("<", "");
                nationality = mrz.Substring(46, 3).Replace("<", "");
                dob = FormatDate(mrz.Substring(49, 6));
                sex = FormatSex(mrz.Substring(56, 1));
                expiry = FormatDate(mrz.Substring(57, 6));
            }
            else
            {
                Con.Warn($"Độ dài MRZ không thuộc chuẩn TD1, TD2, TD3 ({mrz.Length} ký tự).");
                return;
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  ╔═════════════════════ THÔNG TIN CHIP (DG1) ═════════════════════╗");

            PrintRow("Họ và tên", name, ConsoleColor.Yellow);
            Console.WriteLine("  ╟────────────────────────────────────────────────────────────────╢");

            PrintSplitRow("Số giấy tờ", docNum, "Loại", docType);
            PrintSplitRow("Quốc tịch", nationality, "Phát hành", issuingState);
            PrintSplitRow("Ngày sinh", dob, "Giới tính", sex);
            PrintSplitRow("Ngày hết hạn", expiry, "Trạng thái", "Hợp lệ (Verify BAC)");
        }

        private static string ExtractCleanMrz(byte[] dg1)
        {
            for (int i = 0; i < dg1.Length - 2; i++)
            {
                if (dg1[i] == 0x5F && dg1[i + 1] == 0x1F)
                {
                    int len = dg1[i + 2];
                    int offset = i + 3;

                    if (len == 0x81)
                    {
                        len = dg1[i + 3];
                        offset = i + 4;
                    }
                    else if (len == 0x82)
                    {
                        len = (dg1[i + 3] << 8) | dg1[i + 4];
                        offset = i + 5;
                    }

                    if (offset + len <= dg1.Length)
                    {
                        byte[] mrzBytes = new byte[len];
                        Array.Copy(dg1, offset, mrzBytes, 0, len);
                        return Encoding.ASCII.GetString(mrzBytes).Replace("\r", "").Replace("\n", "").Trim();
                    }
                }
            }

            string text = Encoding.ASCII.GetString(dg1);
            int start = 0;
            while (start < text.Length && !char.IsLetterOrDigit(text[start])) start++;
            return text.Substring(start).Replace("\r", "").Replace("\n", "").Trim();
        }

        private static string FormatName(string rawName)
        {
            var parts = rawName.Split(new[] { "<<" }, StringSplitOptions.RemoveEmptyEntries);
            return string.Join(" ", parts).Replace("<", " ").Trim();
        }

        private static string FormatDate(string yymmdd)
        {
            if (yymmdd.Length != 6 || yymmdd.Contains("<")) return yymmdd;

            int year = int.Parse(yymmdd.Substring(0, 2));
            year += (year > (DateTime.Now.Year % 100) + 10) ? 1900 : 2000;

            return $"{yymmdd.Substring(4, 2)}/{yymmdd.Substring(2, 2)}/{year}";
        }

        private static string FormatSex(string s)
        {
            if (s == "M") return "Nam (M)";
            if (s == "F") return "Nữ (F)";
            if (s == "X" || s == "<") return "Không xác định";
            return s;
        }

        private static void PrintRow(string label, string value, ConsoleColor valColor = ConsoleColor.White)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  ║ ");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label,-12}: ");
            Console.ForegroundColor = valColor;
            Console.Write($"{value,-47}");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("║");
        }

        private static void PrintSplitRow(string label1, string val1, string label2, string val2)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write("  ║ ");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"{label1,-12}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{val1,-18}");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"│ {label2,-12}: ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{val2,-13}");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("║");
        }
    }
}