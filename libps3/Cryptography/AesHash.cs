using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace libps3.Cryptography
{
    internal static class AesHash
    {
        // Tips from:
        // https://stackoverflow.com/a/30123190
        // https://github.com/elektronika-ba/tiny-AES-CMAC-c/blob/master/aes_cmac.c
        #region Aes Cmac
        

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void GenerateCmacSubKeys(ReadOnlySpan<byte> key, Span<byte> K1, Span<byte> K2)
        {
            // Step 1. AES-128 with key K is applied to an all-zero input block.
            var emptyIV = K1;
            var L = K2;
            AesCrypto.EncryptCbc(L, key, emptyIV, PaddingMode.None);

            // Step 2. K1 is derived through the following operation:
            ByteOperation.LeftShiftOneBit(L, K1); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((L[0] & 0x80) == 0x80)
                K1[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // Step 3. K2 is derived through the following operation:
            ByteOperation.LeftShiftOneBit(K1, K2); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((K1[0] & 0x80) == 0x80)
                K2[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            // Step 4. (return K1, K2) - already in provided buffers K1 and K2
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Finalize(ReadOnlySpan<byte> key, Span<byte> last, ReadOnlySpan<byte> source, Span<byte> destination, int n)
        {
            // Moved here because the C# compiler doesn't allow you to assign stackalloc spans to out-of-scope variables...

            // Step 5. Clear the necessary part of the destination buffer just in case
            for (byte i = 0; i < 16; i++)
                destination[i] = 0;

            // Step 6. Encrypt each block of the input without needing to allocate an entire buffer of matching size
            Span<byte> emptyIV = stackalloc byte[16];
            for (byte i = 0; i < n - 1; i++)
            {
                ByteOperation.Xor(destination, source.Slice(16 * i, 16), destination, 16); // Y := Mi (+) X
                AesCrypto.EncryptCbc(destination, key, emptyIV, PaddingMode.None); // X := AES-128(KEY, Y);
            }

            // The last block is special due to padding properties
            ByteOperation.Xor(destination, last, destination, 16);
            AesCrypto.EncryptCbc(destination, key, emptyIV, PaddingMode.None);
        }

        internal static int ComputeAesCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            // Step 1. Generate CMAC subkeys
            Span<byte> K1 = stackalloc byte[16];
            Span<byte> K2 = stackalloc byte[16];
            GenerateCmacSubKeys(key, K1, K2);

            // Step 2
            int n = (source.Length + 15) / 16; // n is number of rounds
            int remainder = source.Length % 16; // will need later (optimization for speed)

            // Step 3
            bool isLastBlockComplete = false; // assume last block is not complete block
            if (n == 0)
                n = 1;
            else if (remainder == 0)
                isLastBlockComplete = true; // last block is a complete block

            // Step 4. MAC computing
            int index = 16 * (n - 1);
            if (isLastBlockComplete)
            {
                Span<byte> last = K2; // using the same RAM space for "last" as that of K2 - size optimization
                ByteOperation.Xor(source.Slice(index, 16), K1, last, 16);

                // Do Steps 5 and 6
                Finalize(key, last, source, destination, n);
            }
            else
            {
                Span<byte> last = K1; // using the same RAM space for "last" as that of K1 - size optimization

                // padding input and xoring with K2 at the same time
                for (byte j = 0; j < 16; j++)
                {
                    byte temp = 0x00; // assume padding with 0x00
                    if (j < remainder)
                        temp = source[index + j]; // we have this byte index in input - take it
                    else if (j == remainder)
                        temp = 0x80; // first missing byte byte of input is padded with 0x80

                    last[j] = (byte)(temp ^ K2[j]);
                }

                // Do Steps 5 and 6
                Finalize(key, last, source, destination, n);
            }

            // Step 7. return T (already done in provided "destination" buffer)
            return 16;
        }

        internal static bool CompareAesCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, ReadOnlySpan<byte> hash)
        {
            Span<byte> buffer = stackalloc byte[hash.Length]; // Keep this internal to prevent users causing stackoverflow with buffers
            ComputeAesCmac(key, source, buffer);
            return buffer.SequenceEqual(hash);
        }

        #endregion
    }
}
