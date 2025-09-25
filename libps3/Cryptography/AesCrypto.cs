using libps3.Buffers;
using System;
using System.Security.Cryptography;

namespace libps3.Cryptography
{
    internal static class AesCrypto
    {
        #region Cbc

        public static int DecryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.DecryptCbc(plaintext, iv, destination, paddingMode);
        }

        public static int EncryptCbc(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, Span<byte> destination, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.EncryptCbc(plaintext, iv, destination, paddingMode);
        }

        public static int DecryptCbc(Span<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.DecryptCbc(data, iv, data, paddingMode);
        }

        public static int EncryptCbc(Span<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.EncryptCbc(data, iv, data, paddingMode);
        }

        #endregion

        #region Ecb

        public static int DecryptEcb(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, Span<byte> destination, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.DecryptEcb(plaintext, destination, paddingMode);
        }

        public static int EncryptEcb(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, Span<byte> destination, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.EncryptEcb(plaintext, destination, paddingMode);
        }

        public static int DecryptEcb(Span<byte> data, ReadOnlySpan<byte> key, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.DecryptEcb(data, data, paddingMode);
        }

        public static int EncryptEcb(Span<byte> data, ReadOnlySpan<byte> key, PaddingMode paddingMode = PaddingMode.None)
        {
            using var aes = Aes.Create();
            using var keyBuffer = new SecureBuffer<byte>(key);
            aes.Key = keyBuffer.Buffer;
            return aes.EncryptEcb(data, data, paddingMode);
        }

        #endregion
    }
}
