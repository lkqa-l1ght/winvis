using System.Security.Cryptography;
using System.Text;

namespace MrzProtocol
{
    static class Kdf
    {
        public static byte[] Seed(string mrzKey)
        {
            byte[] h = SHA1.HashData(Encoding.ASCII.GetBytes(mrzKey));
            return Util.Sub(h, 0, 16);
        }

        public static byte[] Des(byte[] seed, int counter)
        {
            byte[] d = Util.Cat(seed, new byte[] { 0, 0, 0, (byte)counter });
            byte[] h = SHA1.HashData(d);
            byte[] k = Util.Sub(h, 0, 16);
            Util.FixDesParity(k);
            return k;
        }
    }
}