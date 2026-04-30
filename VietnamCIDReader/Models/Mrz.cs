using CIDReader.Utils;

namespace CIDReader.Models
{
    class Mrz           // Tạo mã MRZ
    {
        // Lưu các thành phần của mã
        public string DocNum { get; }       // Số CCCD      
        public char CkDoc { get; }          // Check digit cho DocNum
        public string Dob { get; }          // Ngày sinh 
        public char CkDob { get; }          // Check digit cho Dob
        public string Expiry { get; }       // Ngày hết hạn CCCD
        public char CkExp { get; }          // Check digit cho Expiry

        public string Key => DocNum + CkDoc + Dob + CkDob + Expiry + CkExp;         // Tạo mã MRZ từ các thành phần trên

        public Mrz(string raw)  
        {
            raw = raw.Trim().ToUpper();
            if (raw.Length != 24)
                throw new Exception($"Cần đúng 24 ký tự, nhận được {raw.Length}.");

            DocNum = raw[..9];              // 9 kí tự đầu là 9 số cuối CCCD 
            CkDoc = raw[9];                 // Check digit cho DocNum
            Dob = raw[10..16];              // 6 kí tự ngày sinh (dạng YYMMDD)
            CkDob = raw[16];                // Check digit cho ngày sinh
            Expiry = raw[17..23];           // 6 kí tự ngày hết hạn CCCD (dạng YYMMDD)
            CkExp = raw[23];                // Check digit cho ngày hết hạn

            // Kiểm tra tính hợp lệ của các thành phần trong mã

            if (!Util.ValidCK(DocNum, CkDoc))
                throw new Exception($"Check digit số tài liệu sai (kỳ vọng {Util.CheckDigit(DocNum)}, nhận '{CkDoc}').");
            if (!Util.ValidCK(Dob, CkDob))
                throw new Exception($"Check digit ngày sinh sai (kỳ vọng {Util.CheckDigit(Dob)}, nhận '{CkDob}').");
            if (!Util.ValidCK(Expiry, CkExp))
                throw new Exception($"Check digit ngày hết hạn sai (kỳ vọng {Util.CheckDigit(Expiry)}, nhận '{CkExp}').");
        }
    }
}