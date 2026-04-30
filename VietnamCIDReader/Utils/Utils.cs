using System.Security.Cryptography;
using System.Text;

namespace CIDReader.Utils
{
    static class Util               // Chứa các hàm công cụ
    {
        static readonly int[] W = { 7, 3, 1 };

        static int CharVal(char c)              // Chuyển đổi ký tự string sang số
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
            if (c == '<') return 0;
            throw new Exception($"Ký tự MRZ không hợp lệ: '{c}'");
        }

        public static int CheckDigit(string s)          // Tính Check digit
        {
            int sum = 0;
            for (int i = 0; i < s.Length; i++)
                sum += CharVal(s[i]) * W[i % 3];
            return sum % 10;
        }

        public static bool ValidCK(string field, char ck) =>            // Kiểm tra tính hợp lệ
            CheckDigit(field) == (ck - '0');

        public static string Hex(byte[] b) => BitConverter.ToString(b).Replace("-", "");

        public static byte[] XOR(byte[] a, byte[] b)
        {
            byte[] r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
            return r;
        }

        public static byte[] Sub(byte[] src, int off, int len)
        {
            byte[] r = new byte[len];
            Array.Copy(src, off, r, 0, len);
            return r;
        }

        public static byte[] Cat(params byte[][] parts)
        {
            byte[] r = new byte[parts.Sum(p => p.Length)];
            int pos = 0;
            foreach (var p in parts) { p.CopyTo(r, pos); pos += p.Length; }
            return r;
        }

        public static byte[] Rand(int n)
        {
            byte[] b = new byte[n];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        public static void FixDesParity(byte[] key)
        {
            for (int i = 0; i < key.Length; i++)
            {
                int bits = 0;
                for (int b = 1; b < 8; b++) bits += (key[i] >> b) & 1;
                key[i] = (byte)((key[i] & 0xFE) | (bits % 2 == 0 ? 1 : 0));
            }
        }

        public static void PrintReadableText(byte[] data)
        {
            string rawText = Encoding.UTF8.GetString(data);
            Console.WriteLine("  --- NỘI DUNG ĐỌC ĐƯỢC ---");
            foreach (char c in rawText)
            {
                if (!char.IsControl(c) || c == '\n' || c == '\r')
                {
                    Console.Write(c);
                }
                else
                {
                    Console.Write(".");
                }
            }
            Console.WriteLine("\n  -------------------------");
        }
    }
}