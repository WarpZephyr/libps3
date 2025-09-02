using Edoke.IO;
using System.IO;

namespace libps3
{
    public static class NPD
    {
        #region Format

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

        #endregion

        private static bool Is(BinaryStreamReader br)
            => br.Length >= 128 && br.ReadASCII(4, false) == "NPD\0";
    }
}
