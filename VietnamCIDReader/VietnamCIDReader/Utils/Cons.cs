using System;

namespace MrzProtocol
{
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
}