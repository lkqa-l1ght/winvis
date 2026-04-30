namespace CIDReader.SmartCard
{
    class DgReader              // Đọc thông tin từ các file dữ liệu của CCCD (DG1, DG2, DG13)
    {
        private readonly SecureMessaging _sm;
        public DgReader(SecureMessaging sm) => _sm = sm;

        public byte[] ReadDG(byte[] fileId)
        {
            _sm.TransmitAndUnwrap(0x00, 0xA4, 0x02, 0x0C, fileId);

            List<byte> result = new();
            int offset = 0;
            const int chunkSize = 0xE0;

            while (true)
            {
                try
                {
                    byte[] chunk = _sm.TransmitAndUnwrap(
                        0x00, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), null, chunkSize);

                    if (chunk == null || chunk.Length == 0) break;

                    result.AddRange(chunk);
                    offset += chunk.Length;

                    if (chunk.Length < chunkSize) break;
                }
                catch (Exception ex)
                {
                    if (ex.Message.Contains("6B") || ex.Message.Contains("62")) break;
                    throw;
                }
            }
            return result.ToArray();
        }
    }
}