using libps3.Buffers;
using System;
using System.Security.Cryptography;

namespace libps3.Cryptography
{
    internal static class ShaHash
    {
        #region Sha1 Hmac

        internal static int ComputeSha1Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
        {
            using var keyBuffer = new SecureBuffer<byte>(key);
            using var hmac = new HMACSHA1(keyBuffer.Buffer);
            if (!hmac.TryComputeHash(source, destination, out int bytesWritten))
            {
                throw new Exception($"SHA1 HMAC operation failed, is the desination too small?");
            }

            return bytesWritten;
        }

        internal static bool CompareSha1Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, ReadOnlySpan<byte> hash)
        {
            Span<byte> buffer = stackalloc byte[hash.Length]; // Keep this internal to prevent users causing stackoverflow with buffers
            ComputeSha1Hmac(key, source, buffer);
            return buffer.SequenceEqual(hash);
        }

        #endregion
    }
}
