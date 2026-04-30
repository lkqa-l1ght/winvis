using PCSC.Iso7816;
using CIDReader.Utils;

namespace CIDReader.SmartCard
{
    class SecureMessaging
    {
        private readonly IsoReader _iso;
        private readonly byte[] _ksEnc;
        private readonly byte[] _ksMac;
        private readonly byte[] _ssc;

        public SecureMessaging(IsoReader iso, byte[] ksEnc, byte[] ksMac, byte[] ssc)
        {
            _iso = iso;
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _ssc = ssc;
        }

        private void IncrementSSC()
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
            {
                if (++_ssc[i] != 0) break;
            }
        }

        public byte[] TransmitAndUnwrap(byte cla, byte ins, byte p1, byte p2, byte[]? data = null, int? le = null)
        {
            IncrementSSC();

            List<byte> body = new();

            if (data != null && data.Length > 0)
            {
                byte[] enc = EncryptData(data);
                body.Add(0x87);

                int len = enc.Length + 1;
                if (len <= 127) { body.Add((byte)len); }
                else if (len <= 255) { body.Add(0x81); body.Add((byte)len); }
                else { body.Add(0x82); body.Add((byte)(len >> 8)); body.Add((byte)(len & 0xFF)); }

                body.Add(0x01);
                body.AddRange(enc);
            }

            if (le.HasValue)
            {
                body.Add(0x97);
                body.Add(0x01);
                body.Add((byte)le.Value);
            }

            byte[] header = { (byte)(cla | 0x0C), ins, p1, p2 };
            byte[] macInput;

            if (body.Count > 0)
                macInput = Util.Cat(_ssc, Pad(header), Pad(body.ToArray()));
            else
                macInput = Util.Cat(_ssc, Pad(header));

            byte[] mac = CalcMacNoPadding(_ksMac, macInput).Take(8).ToArray();

            body.Add(0x8E);
            body.Add(0x08);
            body.AddRange(mac);

            var apdu = new CommandApdu(IsoCase.Case4Short, _iso.ActiveProtocol)
            {
                CLA = (byte)(cla | 0x0C),
                INS = ins,
                P1 = p1,
                P2 = p2,
                Data = body.ToArray(),
                Le = 0x00
            };

            var resp = _iso.Transmit(apdu);

            IncrementSSC();

            if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
                throw new Exception($"APDU lỗi: {resp.SW1:X2}{resp.SW2:X2}");

            return ParseAndDecryptResponse(resp.GetData());
        }

        private byte[] ParseAndDecryptResponse(byte[] smResp)
        {
            if (smResp == null || smResp.Length == 0) return Array.Empty<byte>();

            int idx = 0;
            byte[] decryptedData = Array.Empty<byte>();
            byte sw1 = 0, sw2 = 0;

            try
            {
                while (idx < smResp.Length)
                {
                    byte tag = smResp[idx++];
                    int len = smResp[idx++];
                    if (len == 0x81) len = smResp[idx++];
                    else if (len == 0x82) { len = (smResp[idx++] << 8) | smResp[idx++]; }

                    if (tag == 0x87)
                    {
                        idx++;
                        byte[] enc = Util.Sub(smResp, idx, len - 1);
                        decryptedData = DecryptData(enc);
                        idx += len - 1;
                    }
                    else if (tag == 0x99)
                    {
                        sw1 = smResp[idx++];
                        sw2 = smResp[idx++];
                    }
                    else if (tag == 0x8E)
                    {
                        idx += len;
                    }
                    else
                    {
                        idx += len;
                    }
                }
            }
            catch { }

            if (sw1 != 0x90 || sw2 != 0x00)
                throw new Exception($"Chip trả về mã lỗi bên trong DO99: {sw1:X2}{sw2:X2}");

            return decryptedData;
        }

        private byte[] CalcMacNoPadding(byte[] kmac, byte[] data)
        {
            byte[] ka = Util.Sub(kmac, 0, 8);
            byte[] kb = Util.Sub(kmac, 8, 8);

            using var desCbc = System.Security.Cryptography.DES.Create();
            desCbc.Mode = System.Security.Cryptography.CipherMode.CBC;
            desCbc.Padding = System.Security.Cryptography.PaddingMode.None;
            desCbc.Key = ka;
            desCbc.IV = new byte[8];

            byte[] cbcOut = desCbc.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            byte[] lastBlock = Util.Sub(cbcOut, cbcOut.Length - 8, 8);

            using var desEcb = System.Security.Cryptography.DES.Create();
            desEcb.Mode = System.Security.Cryptography.CipherMode.ECB;
            desEcb.Padding = System.Security.Cryptography.PaddingMode.None;

            desEcb.Key = kb;
            byte[] dec = desEcb.CreateDecryptor().TransformFinalBlock(lastBlock, 0, 8);

            desEcb.Key = ka;
            return desEcb.CreateEncryptor().TransformFinalBlock(dec, 0, 8);
        }

        private byte[] Pad(byte[] data)
        {
            int pad = 8 - data.Length % 8;
            byte[] buf = new byte[data.Length + pad];
            Array.Copy(data, buf, data.Length);
            buf[data.Length] = 0x80;
            return buf;
        }

        private byte[] EncryptData(byte[] data)
        {
            using var t = System.Security.Cryptography.TripleDES.Create();
            t.Key = Util.Cat(_ksEnc, Util.Sub(_ksEnc, 0, 8));
            t.Mode = System.Security.Cryptography.CipherMode.CBC;
            t.Padding = System.Security.Cryptography.PaddingMode.None;
            t.IV = new byte[8];

            byte[] padded = Pad(data);
            return t.CreateEncryptor().TransformFinalBlock(padded, 0, padded.Length);
        }

        private byte[] DecryptData(byte[] enc)
        {
            using var t = System.Security.Cryptography.TripleDES.Create();
            t.Key = Util.Cat(_ksEnc, Util.Sub(_ksEnc, 0, 8));
            t.Mode = System.Security.Cryptography.CipherMode.CBC;
            t.Padding = System.Security.Cryptography.PaddingMode.None;
            t.IV = new byte[8];

            byte[] padded = t.CreateDecryptor().TransformFinalBlock(enc, 0, enc.Length);

            int i = padded.Length - 1;
            while (i >= 0 && padded[i] == 0x00) i--;
            if (i >= 0 && padded[i] == 0x80)
                return Util.Sub(padded, 0, i);

            return padded;
        }
    }
}