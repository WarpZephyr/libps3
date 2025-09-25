using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace libps3.Cryptography
{
    internal static class CryptoHelper
    {
        #region Decrypt

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] DecryptAesCbc(byte[] key, byte[] data)
            => DecryptAes(key, data, CipherMode.CBC, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] DecryptAesCbc(byte[] key, byte[] iv, byte[] data)
            => DecryptAes(key, iv, data, CipherMode.CBC, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] DecryptAesEcb(byte[] key, byte[] data)
            => DecryptAes(key, data, CipherMode.ECB, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] DecryptAesEcb(byte[] key, byte[] iv, byte[] data)
            => DecryptAes(key, iv, data, CipherMode.ECB, PaddingMode.None);

        internal static byte[] DecryptAes(byte[] key, byte[] iv, byte[] data, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using var aes = Aes.Create();
            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            using var decryptor = aes.CreateDecryptor(key, iv);
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }

        internal static byte[] DecryptAes(byte[] key, byte[] data, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using var aes = Aes.Create();
            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            aes.Key = key;
            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }

        #endregion

        #region Encrypt

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] EncryptAesCbc(byte[] key, byte[] data)
            => EncryptAes(key, data, CipherMode.CBC, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] EncryptAesCbc(byte[] key, byte[] iv, byte[] data)
            => EncryptAes(key, iv, data, CipherMode.CBC, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] EncryptAesEcb(byte[] key, byte[] data)
            => EncryptAes(key, data, CipherMode.ECB, PaddingMode.None);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] EncryptAesEcb(byte[] key, byte[] iv, byte[] data)
            => EncryptAes(key, iv, data, CipherMode.ECB, PaddingMode.None);

        internal static byte[] EncryptAes(byte[] key, byte[] iv, byte[] data, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using var aes = Aes.Create();
            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            using var encryptor = aes.CreateEncryptor(key, iv);
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        internal static byte[] EncryptAes(byte[] key, byte[] data, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using var aes = Aes.Create();
            aes.Mode = cipherMode;
            aes.Padding = paddingMode;
            aes.Key = key;
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        #endregion

        #region Aes Cmac

        // https://stackoverflow.com/a/30123190
        private static byte[] LeftShiftOneBit(byte[] bytes)
        {
            byte[] rotatedBytes = new byte[bytes.Length];
            byte carry = 0;

            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(bytes[i] << 1);
                rotatedBytes[i] = (byte)((u & 0x00FF) + carry);
                carry = (byte)((u & 0xFF00) >> 8);
            }

            return rotatedBytes;
        }

        // https://stackoverflow.com/a/30123190
        internal static byte[] ComputeAesCmac(byte[] key, byte[] input)
        {
            // SubKey generation
            // step 1, AES-128 with key K is applied to an all-zero input block.
            byte[] L = EncryptAesCbc(key, new byte[16], new byte[16]);

            // step 2, K1 is derived through the following operation:
            byte[] K1 = LeftShiftOneBit(L); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
            if ((L[0] & 0x80) == 0x80)
                K1[15] ^= 0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

            // step 3, K2 is derived through the following operation:
            byte[] K2 = LeftShiftOneBit(K1); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
            if ((K1[0] & 0x80) == 0x80)
                K2[15] ^= 0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

            // MAC computing
            if (((input.Length != 0) && (input.Length % 16 == 0)) == true)
            {
                // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
                // the last block shall be exclusive-OR'ed with K1 before processing
                for (int j = 0; j < K1.Length; j++)
                    input[input.Length - 16 + j] ^= K1[j];
            }
            else
            {
                // Otherwise, the last block shall be padded with 10^i
                byte[] padding = new byte[16 - input.Length % 16];
                padding[0] = 0x80;

                input = [.. input, .. padding.AsEnumerable()];

                // and exclusive-OR'ed with K2
                for (int j = 0; j < K2.Length; j++)
                    input[input.Length - 16 + j] ^= K2[j];
            }

            // The result of the previous process will be the input of the last encryption.
            byte[] encResult = EncryptAesCbc(key, new byte[16], input);
            byte[] hashValue = new byte[16];
            Array.Copy(encResult, encResult.Length - hashValue.Length, hashValue, 0, hashValue.Length);

            return hashValue;
        }

        internal static bool CompareAesCmac(byte[] key, byte[] input, byte[] hash)
            => ComputeAesCmac(key, input).SequenceEqual(hash);

        #endregion

        #region Sha1 Hmac

        internal static byte[] ComputeSha1Hmac(byte[] key, byte[] input)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(input);
        }

        internal static bool CompareSha1Hmac(byte[] key, byte[] input, byte[] hash)
            => ComputeSha1Hmac(key, input).SequenceEqual(hash);

        #endregion
    }
}
