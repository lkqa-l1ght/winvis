using PCSC.Iso7816;

namespace CIDReader.SmartCard
{
    class PassportChip                  // Thực hiện giao tiếp với đầu đọc CCCD
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
}