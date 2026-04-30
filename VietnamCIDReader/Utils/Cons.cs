namespace CIDReader.Utils
{
    static class Con
    {
        public static void Err(string msg)                  // In lỗi
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ✘  {msg}");
            Console.ResetColor();
        }

        public static void Warn(string msg)                 // In cảnh báo
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  ⚠  {msg}");
            Console.ResetColor();
        }
    }
}