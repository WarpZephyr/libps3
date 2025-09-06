using Edoke.IO;
using System.IO;

namespace libps3
{
    public static class NPD
    {
        #region Is

        public static bool Is(string path)
        {
            using BinaryStreamReader br = new BinaryStreamReader(path, true);
            return Is(br);
        }

        public static bool Is(byte[] bytes)
        {
            using BinaryStreamReader br = new BinaryStreamReader(bytes, true);
            return Is(br);
        }

        public static bool Is(Stream stream)
        {
            using BinaryStreamReader br = new BinaryStreamReader(stream, true);
            return Is(br);
        }

        private static bool Is(BinaryStreamReader br)
            => br.Length >= 128 && br.ReadASCII(4, false) == "NPD\0";

        #endregion

        #region GetContentId

        public static string GetContentId(string path)
        {
            using BinaryStreamReader br = new BinaryStreamReader(path, true);
            return GetContentId(br);
        }

        public static string GetContentId(byte[] bytes)
        {
            using BinaryStreamReader br = new BinaryStreamReader(bytes, true);
            return GetContentId(br);
        }

        public static string GetContentId(Stream stream)
        {
            using BinaryStreamReader br = new BinaryStreamReader(stream, true);
            return GetContentId(br);
        }

        private static string GetContentId(BinaryStreamReader br)
            => new NpdHeader(br).contentID.Replace("\0", string.Empty);

        #endregion
    }
}
