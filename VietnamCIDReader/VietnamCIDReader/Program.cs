using PCSC;
using PCSC.Iso7816;
using System;
using System.Formats.Asn1;
using System.IO;
using System.Text;

namespace MrzProtocol
{
    class Program
    {
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

                Console.WriteLine("\n[1] Đang đọc DG1 (MRZ)...");
                byte[] dg1 = dgReader.ReadDG(new byte[] { 0x01, 0x01 });
                MrzFormatter.PrintBeautiful(dg1);

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

                Console.WriteLine("\n[3] Đang đọc DG2 (Ảnh chân dung)...");
                byte[] dg2 = dgReader.ReadDG(new byte[] { 0x01, 0x02 });

                if (dg2.Length > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"Đọc thành công toàn bộ DG2: {dg2.Length} bytes.");
                    Console.ResetColor();

                    byte[] imageBytes = ImageExtractor.ExtractImageBytesFromDG2(dg2);

                    if (imageBytes.Length > 0)
                    {
                        byte[] realImageBytes = ImageExtractor.GetRealImageFromBiometricBlock(imageBytes);
                        string imageBase64String = Convert.ToBase64String(realImageBytes);

                        Console.WriteLine($"Đã trích xuất thành công dữ liệu ảnh gốc: {realImageBytes.Length} bytes.");

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