using PCSC;
using PCSC.Iso7816;
using System.Text;
using CIDReader.Models;
using CIDReader.Utils;
using CIDReader.SmartCard;
using CIDReader.Parsers;

namespace CIDReader
{
    class Program
    {
        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("ĐỌC DỮ LIỆU CCCD");
            Console.WriteLine();

            Mrz? mrz = null;
            while (mrz == null)
            {
                Console.Write("Nhập MRZ: ");
                string? input = Console.ReadLine();
                try { mrz = new Mrz(input ?? ""); }
                catch (Exception ex) { Con.Err(ex.Message); }
            }

            try
            {
                using var context = ContextFactory.Instance.Establish(SCardScope.System);
                var readers = context.GetReaders();
                if (readers == null || readers.Length == 0) throw new Exception("Không tìm thấy đầu đọc.");

                using var iso = new IsoReader(context, readers[0], SCardShareMode.Shared, SCardProtocol.Any, false);

                // Thực hiện BAC để lấy quyền truy cập chip
                var (chipKsEnc, chipKsMac, chipSsc) = new Bac(mrz, iso).Run();

                var sm = new SecureMessaging(iso, chipKsEnc, chipKsMac, chipSsc);
                var dgReader = new DgReader(sm);

                // Đọc và in dữ liệu DG1 (Thông tin MRZ)
                Console.WriteLine("\n[THÔNG TIN CÁ NHÂN]");
                byte[] dg1 = dgReader.ReadDG(DataGroup.DG1);
                MrzFormatter.PrintBeautiful(dg1);

                // Đọc và xử lý DG13 (Thông tin bổ sung)
                Console.WriteLine("\n[THÔNG TIN BỔ SUNG]");
                byte[] dg13 = dgReader.ReadDG(DataGroup.DG13);
                if (dg13.Length > 0)
                {
                    TlvParser.ExtractDG13(dg13); // In ra màn hình
                }

                // Đọc DG2
                Console.WriteLine("\n[ẢNH CHÂN DUNG]");
                byte[] dg2 = dgReader.ReadDG(DataGroup.DG2);
                if (dg2.Length > 0)
                {
                    byte[] imageBytes = ImageExtractor.ExtractImageBytesFromDG2(dg2);
                    if (imageBytes.Length > 0)
                    {
                        byte[] realImageBytes = ImageExtractor.GetRealImageFromBiometricBlock(imageBytes);
                        // In mã Base64
                        Console.WriteLine($"+ Base64: {Convert.ToBase64String(realImageBytes).Substring(0, 50)}...");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Lỗi: {ex.Message}");
                Console.ResetColor();
            }

            Console.WriteLine("\nNhấn Enter để kết thúc.");
            Console.ReadLine();
        }
    }
}