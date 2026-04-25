using PCSC;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace MrzProtocol
{
    // ══════════════════════════════════════════════════════════
    // TIỆN ÍCH
    // ══════════════════════════════════════════════════════════
    static class Util
    {
        static readonly int[] W = { 7, 3, 1 };

        static int CharVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
            if (c == '<') return 0;
            throw new Exception($"Ký tự MRZ không hợp lệ: '{c}'");
        }

        public static int CheckDigit(string s)
        {
            int sum = 0;
            for (int i = 0; i < s.Length; i++)
                sum += CharVal(s[i]) * W[i % 3];
            return sum % 10;
        }

        public static bool ValidCK(string field, char ck) =>
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

    // ══════════════════════════════════════════════════════════
    // PARSE & VALIDATE MRZ 24 KÝ TỰ
    // ══════════════════════════════════════════════════════════
    class Mrz
    {
        public string DocNum { get; }
        public char CkDoc { get; }
        public string Dob { get; }
        public char CkDob { get; }
        public string Expiry { get; }
        public char CkExp { get; }

        public string Key => DocNum + CkDoc + Dob + CkDob + Expiry + CkExp;

        public Mrz(string raw)
        {
            raw = raw.Trim().ToUpper();
            if (raw.Length != 24)
                throw new Exception($"Cần đúng 24 ký tự, nhận được {raw.Length}.");

            DocNum = raw[..9];
            CkDoc = raw[9];
            Dob = raw[10..16];
            CkDob = raw[16];
            Expiry = raw[17..23];
            CkExp = raw[23];

            if (!Util.ValidCK(DocNum, CkDoc))
                throw new Exception($"Check digit số tài liệu sai (kỳ vọng {Util.CheckDigit(DocNum)}, nhận '{CkDoc}').");
            if (!Util.ValidCK(Dob, CkDob))
                throw new Exception($"Check digit ngày sinh sai (kỳ vọng {Util.CheckDigit(Dob)}, nhận '{CkDob}').");
            if (!Util.ValidCK(Expiry, CkExp))
                throw new Exception($"Check digit ngày hết hạn sai (kỳ vọng {Util.CheckDigit(Expiry)}, nhận '{CkExp}').");
        }
    }

    // ══════════════════════════════════════════════════════════
    // KEY DERIVATION (ICAO 9303)
    // ══════════════════════════════════════════════════════════
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

    // ══════════════════════════════════════════════════════════
    // 3DES HELPERS
    // ══════════════════════════════════════════════════════════
    static class Des3
    {
        public static byte[] Mac(byte[] kmac, byte[] data)
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

        static byte[] DesEcb(byte[] key, byte[] block)
        {
            using var d = DES.Create();
            d.Key = key; d.IV = new byte[8];
            d.Mode = CipherMode.ECB; d.Padding = PaddingMode.None;
            return d.CreateEncryptor().TransformFinalBlock(block, 0, 8);
        }

        static byte[] DesEcbDec(byte[] key, byte[] block)
        {
            using var d = DES.Create();
            d.Key = key; d.IV = new byte[8];
            d.Mode = CipherMode.ECB; d.Padding = PaddingMode.None;
            return d.CreateDecryptor().TransformFinalBlock(block, 0, 8);
        }

        public static byte[] Decrypt(byte[] kenc, byte[] iv, byte[] data)
        {
            using var t = TripleDES.Create();
            t.Key = Util.Cat(kenc, Util.Sub(kenc, 0, 8));
            t.IV = iv;
            t.Mode = CipherMode.CBC;
            t.Padding = PaddingMode.None;

            return t.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
        }

        public static byte[] EncryptNoPadding(byte[] kenc, byte[] iv, byte[] data)
        {
            using var t = TripleDES.Create();
            t.Key = Util.Cat(kenc, Util.Sub(kenc, 0, 8));
            t.IV = iv;
            t.Mode = CipherMode.CBC;
            t.Padding = PaddingMode.None;

            return t.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }

    // ══════════════════════════════════════════════════════════
    // CONSOLE OUTPUT
    // ══════════════════════════════════════════════════════════
    static class Con
    {
        public static void Err(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ✘  {msg}");
            Console.ResetColor();
        }

        public static void Warn(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ⚠  {msg}");
            Console.ResetColor();
        }
    }

    // ══════════════════════════════════════════════════════════
    // BAC
    // ══════════════════════════════════════════════════════════
    class Bac
    {
        private readonly Mrz _mrz;
        private readonly IsoReader _iso;

        public Bac(Mrz mrz, IsoReader iso)
        {
            _mrz = mrz;
            _iso = iso;
        }

        public (byte[] KSenc, byte[] KSmac, byte[] SSC) Run()
        {
            var chip = new PassportChip(_iso);
            chip.SelectLdsApp();

            byte[] rndIcc = chip.GetChallenge();

            byte[] seed = Kdf.Seed(_mrz.Key);
            byte[] kenc = Kdf.Des(seed, 1);
            byte[] kmac = Kdf.Des(seed, 2);

            byte[] rndIfd = Util.Rand(8);
            byte[] kIfd = Util.Rand(16);

            byte[] s = Util.Cat(rndIfd, rndIcc, kIfd);

            byte[] eIfd = Des3.EncryptNoPadding(kenc, new byte[8], s);

            byte[] mIfd = Des3.Mac(kmac, eIfd).Take(8).ToArray();

            byte[] cmdData = Util.Cat(eIfd, mIfd);

            Console.WriteLine($"BAC cmd length = {cmdData.Length}");

            var apdu = new CommandApdu(IsoCase.Case4Short, _iso.ActiveProtocol)
            {
                CLA = 0x00,
                INS = 0x82,
                P1 = 0x00,
                P2 = 0x00,
                Data = cmdData,
                Le = 0
            };

            var resp = _iso.Transmit(apdu);

            if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
                throw new Exception($"BAC auth lỗi: {resp.SW1:X2}{resp.SW2:X2}");

            byte[] respData = resp.GetData();

            byte[] eIcc = Util.Sub(respData, 0, 32);
            byte[] mIcc = Util.Sub(respData, 32, 8);

            // Verify MAC response
            byte[] expectedMac = Des3.Mac(kmac, eIcc);
            if (!mIcc.SequenceEqual(expectedMac.Take(8)))
                throw new Exception("MAC BAC response không hợp lệ");

            // Decrypt response
            byte[] sIcc = Des3.Decrypt(kenc, new byte[8], eIcc);

            byte[] rndIccResp = Util.Sub(sIcc, 0, 8);
            byte[] rndIfdResp = Util.Sub(sIcc, 8, 8);
            byte[] kIcc = Util.Sub(sIcc, 16, 16);

            if (!rndIccResp.SequenceEqual(rndIcc))
                throw new Exception("RND.ICC không khớp");

            if (!rndIfdResp.SequenceEqual(rndIfd))
                throw new Exception("RND.IFD không khớp");

            byte[] kSeed = Util.XOR(kIfd, kIcc);

            byte[] ksEnc = Kdf.Des(kSeed, 1);
            byte[] ksMac = Kdf.Des(kSeed, 2);
            byte[] ssc = Util.Cat(Util.Sub(rndIcc, 4, 4), Util.Sub(rndIfd, 4, 4));

            return (ksEnc, ksMac, ssc);
        }
    }

    class PassportChip
    {
        private readonly IsoReader _iso;

        public PassportChip(IsoReader iso)
        {
            _iso = iso;
        }

        public void SelectLdsApp()
        {
            byte[] aid = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

            var apdu = new CommandApdu(IsoCase.Case4Short, _iso.ActiveProtocol)
            {
                CLA = 0x00,
                INS = 0xA4,
                P1 = 0x04,
                P2 = 0x0C,
                Data = aid,
                Le = 0
            };

            var resp = _iso.Transmit(apdu);

            if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
                throw new Exception($"SELECT LDS lỗi: {resp.SW1:X2}{resp.SW2:X2}");
        }

        public byte[] GetChallenge()
        {
            var apdu = new CommandApdu(IsoCase.Case2Short, _iso.ActiveProtocol)
            {
                CLA = 0x00,
                INS = 0x84,
                P1 = 0x00,
                P2 = 0x00,
                Le = 8
            };

            var resp = _iso.Transmit(apdu);

            if (resp.SW1 != 0x90 || resp.SW2 != 0x00)
                throw new Exception($"GET CHALLENGE lỗi: {resp.SW1:X2}{resp.SW2:X2}");

            return resp.GetData();
        }
    }

    // ══════════════════════════════════════════════════════════
    // SECURE MESSAGING (ICAO 9303)
    // ══════════════════════════════════════════════════════════
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

        public byte[] TransmitAndUnwrap(
            byte cla, byte ins, byte p1, byte p2, byte[]? data = null, int? le = null)
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

    // ══════════════════════════════════════════════════════════
    // ĐỌC DỮ LIỆU FILE DG1
    // ══════════════════════════════════════════════════════════
    class DgReader
    {
        private readonly SecureMessaging _sm;
        public DgReader(SecureMessaging sm) => _sm = sm;

        public byte[] ReadDG(byte[] fileId)
        {
            // Select File
            _sm.TransmitAndUnwrap(0x00, 0xA4, 0x02, 0x0C, fileId);

            List<byte> result = new();
            int offset = 0;
            const int chunkSize = 0xE0;

            while (true)
            {
                try
                {
                    byte[] chunk = _sm.TransmitAndUnwrap(
                        0x00, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), null, chunkSize);

                    if (chunk == null || chunk.Length == 0) break;

                    result.AddRange(chunk);
                    offset += chunk.Length;

                    if (chunk.Length < chunkSize) break;
                }
                catch (Exception ex)
                {
                    // Lỗi 6B00 (Offset outside) hoặc 6282 (End of file) thường gặp khi đọc xong
                    if (ex.Message.Contains("6B") || ex.Message.Contains("62")) break;
                    throw;
                }
            }
            return result.ToArray();
        }
    }

    // ══════════════════════════════════════════════════════════
    // MRZ FORMATTER & PARSER
    // ══════════════════════════════════════════════════════════
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
            string formatted = string.Join(" ", parts).Replace("<", " ").Trim();
            return formatted;
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


    // ══════════════════════════════════════════════════════════
    // MAIN
    // ══════════════════════════════════════════════════════════
    class Program
    {
        static class TlvParser
        {
            private static readonly string[] Dg13Labels = new string[]
            {
                "Số CCCD",            // 0
                "Họ và tên",          // 1
                "Ngày sinh",          // 2
                "Giới tính",          // 3
                "Quốc tịch",          // 4
                "Dân tộc",            // 5
                "Tôn giáo",           // 6
                "Quê quán",           // 7
                "Nơi thường trú",     // 8
                "Đặc điểm nhận dạng", // 9
                "Ngày cấp",           // 10
                "Ngày hết hạn",       // 11
                "Họ tên cha",         // 12 
                "Họ tên mẹ",          // 13 
                "Tag C"               // 14 
            };

            private static int _textIndex = 0;

            public static void ExtractDG13(byte[] data)
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

        // --- CÁC HÀM XỬ LÝ ẢNH ---
        static byte[] ExtractImageBytesFromDG2(byte[] dg2Raw)
        {
            for (int i = 0; i < dg2Raw.Length - 2; i++)
            {
                if (dg2Raw[i] == 0x5F && dg2Raw[i + 1] == 0x2E)
                {
                    int len = dg2Raw[i + 2];
                    int offset = i + 3;

                    if (len == 0x81) { len = dg2Raw[i + 3]; offset = i + 4; }
                    else if (len == 0x82) { len = (dg2Raw[i + 3] << 8) | dg2Raw[i + 4]; offset = i + 5; }
                    else if (len == 0x83) { len = (dg2Raw[i + 3] << 16) | (dg2Raw[i + 4] << 8) | dg2Raw[i + 5]; offset = i + 6; }
                    else if (len == 0x84) { len = (dg2Raw[i + 3] << 24) | (dg2Raw[i + 4] << 16) | (dg2Raw[i + 5] << 8) | dg2Raw[i + 6]; offset = i + 7; }

                    if (offset + len <= dg2Raw.Length)
                    {
                        byte[] imageBytes = new byte[len];
                        Array.Copy(dg2Raw, offset, imageBytes, 0, len);
                        return imageBytes;
                    }
                }
            }
            return Array.Empty<byte>();
        }

        static byte[] GetRealImageFromBiometricBlock(byte[] biometricBlock)
        {
            byte[] jp2kMagicBytes = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20 };
            byte[] jpegMagicBytes = { 0xFF, 0xD8, 0xFF };

            for (int i = 0; i < biometricBlock.Length - 8; i++)
            {
                if (biometricBlock.Skip(i).Take(8).SequenceEqual(jp2kMagicBytes))
                {
                    return biometricBlock.Skip(i).ToArray();
                }

                if (biometricBlock.Skip(i).Take(3).SequenceEqual(jpegMagicBytes))
                {
                    return biometricBlock.Skip(i).ToArray();
                }
            }

            return biometricBlock;
        }

        // --- HÀM MAIN ---
        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("Đọc thông tin CCCD");
            Console.ResetColor();
            Console.WriteLine();

            Mrz? mrz = null;
            while (mrz == null)
            {
                Console.Write("  Nhập MRZ: ");
                string? input = Console.ReadLine();

                try
                {
                    mrz = new Mrz(input ?? "");
                }
                catch (Exception ex)
                {
                    Con.Err(ex.Message);
                }
            }

            try
            {
                using var context = ContextFactory.Instance.Establish(SCardScope.System);
                var readers = context.GetReaders();

                if (readers == null || readers.Length == 0)
                    throw new Exception("Không tìm thấy đầu đọc NFC");

                Console.WriteLine();
                Console.WriteLine($"Đang dùng reader: {readers[0]}");

                using var iso = new IsoReader(
                    context,
                    readers[0],
                    SCardShareMode.Shared,
                    SCardProtocol.Any,
                    false);

                Console.WriteLine("Đang thực hiện BAC với chip...");
                var (chipKsEnc, chipKsMac, chipSsc) = new Bac(mrz, iso).Run();
                PrintResult("BAC", chipKsEnc, chipKsMac, chipSsc);

                var sm = new SecureMessaging(iso, chipKsEnc, chipKsMac, chipSsc);
                var dgReader = new DgReader(sm);

                // Đọc DG1
                Console.WriteLine("\n[1] Đang đọc DG1 (MRZ)...");
                byte[] dg1 = dgReader.ReadDG(new byte[] { 0x01, 0x01 });
                MrzFormatter.PrintBeautiful(dg1);

                // Đọc DG13
                Console.WriteLine("\n[2] Đang đọc DG13 (Thông tin bổ sung)...");
                byte[] dg13 = dgReader.ReadDG(new byte[] { 0x01, 0x0D });

                if (dg13.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Đọc thành công DG13: {dg13.Length} bytes.");
                    Console.ResetColor();

                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    string filePath = Path.Combine(desktopPath, "DG13_raw.bin");

                    File.WriteAllBytes(filePath, dg13);
                    Console.WriteLine($"Đã lưu file thô DG13 ra: {filePath}");

                    TlvParser.ExtractDG13(dg13);
                }

                // Đọc DG2
                Console.WriteLine("\n[3] Đang đọc DG2 (Ảnh chân dung)...");
                byte[] dg2 = dgReader.ReadDG(new byte[] { 0x01, 0x02 });

                if (dg2.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Đọc thành công toàn bộ DG2: {dg2.Length} bytes.");
                    Console.ResetColor();

                    byte[] imageBytes = ExtractImageBytesFromDG2(dg2);

                    if (imageBytes.Length > 0)
                    {
                        // Lọc lấy ảnh
                        byte[] realImageBytes = GetRealImageFromBiometricBlock(imageBytes);

                        // Convert sang Base64
                        string imageBase64String = Convert.ToBase64String(realImageBytes);

                        Console.WriteLine($"Đã trích xuất thành công dữ liệu ảnh gốc: {realImageBytes.Length} bytes.");

                        // Lưu ra Desktop
                        string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                        string base64FilePath = Path.Combine(desktopPath, "FaceImage_Base64.txt");

                        File.WriteAllText(base64FilePath, imageBase64String);

                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Đã xuất mã Base64 sạch của ảnh ra màn hình Desktop:");
                        Console.WriteLine($"  -> {base64FilePath}");
                        Console.ResetColor();
                    }
                    else
                    {
                        Con.Warn("Không tìm thấy tag ảnh (5F 2E) trong dữ liệu DG2.");
                    }
                }
            }
            catch (Exception ex)
            {
                Con.Err(ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("Nhấn Enter để thoát...");
            Console.ReadLine();
        }

        static void PrintResult(string proto, byte[] ksEnc, byte[] ksMac, byte[]? ssc)
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ══ SESSION KEYS ══════════════════════════════════════════════");
            Console.WriteLine($"  Giao thức : {proto}");
            Console.WriteLine($"  KSenc     : {Util.Hex(ksEnc)}");
            Console.WriteLine($"  KSmac     : {Util.Hex(ksMac)}");
            if (ssc != null)
                Console.WriteLine($"  SSC       : {Util.Hex(ssc)}");
            Console.WriteLine("  ══════════════════════════════════════════════════════════════");
            Console.ResetColor();
        }
    }
}