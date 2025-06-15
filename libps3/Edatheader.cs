using Edoke.IO;

namespace libps3
{
    internal readonly struct EdatHeader
    {
        /// <summary>
        /// Flags describing various things, may be several values.
        /// </summary>
        public readonly uint flags;

        /// <summary>
        /// Block size.
        /// </summary>
        public readonly int blockSize;

        /// <summary>
        /// The size of the decrypted data.
        /// </summary>
        public readonly ulong dataSize;

        internal EdatHeader(BinaryStreamReader br)
        {
            br.BigEndian = true;
            flags = br.ReadUInt32();
            blockSize = br.ReadInt32();
            dataSize = br.ReadUInt64();
        }

        internal EdatHeader(BinaryMemoryReader br)
        {
            br.BigEndian = true;
            flags = br.ReadUInt32();
            blockSize = br.ReadInt32();
            dataSize = br.ReadUInt64();
        }
    }
}
