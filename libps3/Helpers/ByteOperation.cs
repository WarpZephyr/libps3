using System;
using System.Runtime.CompilerServices;

namespace libps3
{
    internal static class ByteOperation
    {
        public static byte[] Xor(byte[] a, byte[] b)
        {
            int length = Math.Min(a.Length, b.Length);
            byte[] result = new byte[length];

            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }

            return result;
        }

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

        public static void Xor(byte[] a, byte[] b, Span<byte> result)
        {
            int length = Math.Min(result.Length, Math.Min(a.Length, b.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        public static void Xor(byte[] a, byte[] b, byte[] result)
        {
            int length = Math.Min(result.Length, Math.Min(a.Length, b.Length));
            for (int i = 0; i < length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
        }

        public static void LeftShiftOneBit(Span<byte> source, Span<byte> destination)
        {
            byte carry = 0;

            for (int i = source.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(source[i] << 1);
                destination[i] = (byte)((u & 0x00FF) + carry);
                carry = (byte)((u & 0xFF00) >> 8);
            }
        }

        public static bool EqualTo(this byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
