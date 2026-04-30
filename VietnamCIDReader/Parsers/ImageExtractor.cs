namespace CIDReader.Parsers
{
    static class ImageExtractor             // Lấy thông tin ảnh từ DG2
    {
        public static byte[] ExtractImageBytesFromDG2(byte[] dg2Raw)
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

        public static byte[] GetRealImageFromBiometricBlock(byte[] biometricBlock)
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
    }
}