using System;

namespace MrzProtocol
{
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
}