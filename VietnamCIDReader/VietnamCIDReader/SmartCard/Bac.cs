using PCSC.Iso7816;
using CIDReader.Crypto;
using CIDReader.Utils;
using CIDReader.Models;

namespace CIDReader.SmartCard
{
    class Bac               // Thực hiện giao thức hai chiều theo chuẩn BAC
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

            byte[] expectedMac = Des3.Mac(kmac, eIcc);
            if (!mIcc.SequenceEqual(expectedMac.Take(8)))
                throw new Exception("MAC BAC response không hợp lệ");

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
}