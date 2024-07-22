namespace libps3
{
    public static class ByteOperation
    {
        public static byte[] XOR(byte[] inputA, byte[] inputB)
        {
            int length = Math.Min(inputA.Length, inputB.Length);
            byte[] result = new byte[length];

            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(inputA[i] ^ inputB[i]);
            }

            return result;
        }

        public static void XOR(Span<byte> inputA, Span<byte> inputB, Span<byte> result)
        {
            int length = Math.Min(result.Length, Math.Min(inputA.Length, inputB.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(inputA[i] ^ inputB[i]);
            }
        }

        public static void XOR(byte[] inputA, byte[] inputB, Span<byte> result)
        {
            int length = Math.Min(result.Length, Math.Min(inputA.Length, inputB.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(inputA[i] ^ inputB[i]);
            }
        }

        public static void XOR(byte[] inputA, byte[] inputB, byte[] result)
        {
            int length = Math.Min(result.Length, Math.Min(inputA.Length, inputB.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(inputA[i] ^ inputB[i]);
            }
        }

        public static bool EqualTo(this byte[] bytesA, byte[] bytesB)
        {
            if (bytesA.Length != bytesB.Length)
            {
                return false;
            }

            for (int i = 0; i <  bytesA.Length; i++)
            {
                if (bytesA[i] != bytesB[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
