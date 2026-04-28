using System.Security.Cryptography;
using CIDReader.Utils;

namespace CIDReader.Crypto
{
    static class Des3
    {
        public static byte[] Mac(byte[] kmac, byte[] data)                  // Hàm tính toán mã xác thực MAC
        {
            int pad = 8 - data.Length % 8;
            byte[] buf = new byte[data.Length + pad];
            Array.Copy(data, buf, data.Length);
            buf[data.Length] = 0x80;

            byte[] ka = Util.Sub(kmac, 0, 8);
            byte[] kb = Util.Sub(kmac, 8, 8);

            byte[] cv = new byte[8];
            for (int i = 0; i < buf.Length; i += 8)
                cv = DesEcb(ka, Util.XOR(cv, Util.Sub(buf, i, 8)));

            return DesEcb(ka, DesEcbDec(kb, cv));
        }

        static byte[] DesEcb(byte[] key, byte[] block)                 // Hàm tiện ích hỗ trợ tính toán
        {
            using var d = DES.Create();
            d.Key = key; d.IV = new byte[8];
            d.Mode = CipherMode.ECB; d.Padding = PaddingMode.None;
            return d.CreateEncryptor().TransformFinalBlock(block, 0, 8);
        }

        static byte[] DesEcbDec(byte[] key, byte[] block)              // Hàm tiện ích hỗ trợ tính toán
        {
            using var d = DES.Create();
            d.Key = key; d.IV = new byte[8];
            d.Mode = CipherMode.ECB; d.Padding = PaddingMode.None;
            return d.CreateDecryptor().TransformFinalBlock(block, 0, 8);
        }

        public static byte[] EncryptNoPadding(byte[] kenc, byte[] iv, byte[] data)      // Mã hóa dữ liệu các lệnh ADPU
        {
            using var t = TripleDES.Create();
            t.Key = Util.Cat(kenc, Util.Sub(kenc, 0, 8));
            t.IV = iv;
            t.Mode = CipherMode.CBC;
            t.Padding = PaddingMode.None;

            return t.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] Decrypt(byte[] kenc, byte[] iv, byte[] data)               // Giải mã
        {
            using var t = TripleDES.Create();
            t.Key = Util.Cat(kenc, Util.Sub(kenc, 0, 8));
            t.IV = iv;
            t.Mode = CipherMode.CBC;
            t.Padding = PaddingMode.None;

            return t.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
        }

    }
}