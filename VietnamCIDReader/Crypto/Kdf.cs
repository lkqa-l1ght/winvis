using System.Security.Cryptography;
using System.Text;
using CIDReader.Utils;

namespace CIDReader.Crypto
{
    static class Kdf            // Sinh ra các mã khóa cho chuỗi MRZ theo chuẩn BAC
    {
        public static byte[] Seed(string mrzKey)                    // Sinh khóa ban đầu Kseed
        {
            byte[] h = SHA1.HashData(Encoding.ASCII.GetBytes(mrzKey));
            return Util.Sub(h, 0, 16);
        }

        public static byte[] Des(byte[] seed, int counter)          // Sinh khóa phiên
        {
            byte[] d = Util.Cat(seed, new byte[] { 0, 0, 0, (byte)counter });
            byte[] h = SHA1.HashData(d);
            byte[] k = Util.Sub(h, 0, 16);
            Util.FixDesParity(k);
            return k;
        }
    }
}