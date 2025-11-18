using System;
using System.Runtime.CompilerServices;

namespace libps3.Helpers
{
    internal static class ByteOperation
    {
        public static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
        {
            int length = Math.Min(result.Length, Math.Min(a.Length, b.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, int length)
        {
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        public static void LeftShiftOneBit(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            byte carry = 0;

            for (int i = source.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(source[i] << 1);
                destination[i] = (byte)((u & 0x00FF) + carry);
                carry = (byte)((u & 0xFF00) >> 8);
            }
        }

        public static bool IsZero(ReadOnlySpan<byte> source)
        {
            for (int i = 0; i < source.Length; i++)
            {
                if (source[i] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
