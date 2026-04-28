namespace CIDReader.SmartCard
{
    public static class DataGroup               // Định nghĩa các file dữ liệu trong CCCD
    {
        public static readonly byte[] DG1 = { 0x01, 0x01 };         // Đọc dữ liệu cho DG1
        public static readonly byte[] DG2 = { 0x01, 0x02 };         // Đọc dữ liệu cho DG2
        public static readonly byte[] DG13 = { 0x01, 0x0D };        // Đọc dữ liệu cho DG13
    }
}
