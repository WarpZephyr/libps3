using Edoke.IO;
using libps3.Cryptography;
using System.Text;

namespace libps3
{
    internal readonly struct NpdHeader
    {
        public readonly string magic;
        public readonly uint version;
        public readonly uint license;
        public readonly uint type;
        public readonly string contentID;
        public readonly byte[] digest;
        public readonly byte[] titleHash;
        public readonly byte[] headerHash;
        public readonly ulong activateTime;
        public readonly ulong expireTime;

        internal NpdHeader(BinaryStreamReader br)
        {
            br.BigEndian = true;
            magic = br.AssertASCII(["NPD\0", "\0\0\0\0"]);
            version = br.ReadUInt32();
            license = br.ReadUInt32();
            type = br.ReadUInt32();
            contentID = br.ReadASCII(48);
            digest = br.ReadBytes(16);
            titleHash = br.ReadBytes(16);
            headerHash = br.ReadBytes(16);
            activateTime = br.ReadUInt64();
            expireTime = br.ReadUInt64();
        }

        internal NpdHeader(BinaryMemoryReader br)
        {
            br.BigEndian = true;
            magic = br.AssertASCII(["NPD\0", "\0\0\0\0"]);
            version = br.ReadUInt32();
            license = br.ReadUInt32();
            type = br.ReadUInt32();
            contentID = br.ReadASCII(48);
            digest = br.ReadBytes(16);
            titleHash = br.ReadBytes(16);
            headerHash = br.ReadBytes(16);
            activateTime = br.ReadUInt64();
            expireTime = br.ReadUInt64();
        }

        internal byte[] GetHeaderBytes()
        {
            byte[] headerHashBytes = new byte[0x60];
            var bw = new BinarySpanWriter(headerHashBytes, true);
            bw.WriteASCII(magic, 4, 0);
            bw.WriteUInt32(version);
            bw.WriteUInt32(license);
            bw.WriteUInt32(type);
            bw.WriteASCII(contentID, 48, 0);
            bw.WriteBytes(digest);
            bw.WriteBytes(titleHash);
            return headerHashBytes;
        }

        internal byte[] HashTitle(string filename)
            => CryptoHelper.AESCMAC(KeyVault.NP_TITLE_OMAC_KEY, new ASCIIEncoding().GetBytes(contentID + filename));

        internal byte[] HashHeader(byte[] klicensee)
            => CryptoHelper.AESCMAC(ByteOperation.XOR(klicensee, KeyVault.NP_HEADER_OMAC_KEY), GetHeaderBytes());

        public bool TitleHashValid(string filename)
            => ByteOperation.EqualTo(HashTitle(filename), titleHash);

        public bool HeaderValid(byte[] klicensee)
            => headerHash.EqualTo(HashHeader(klicensee));

        public bool HashesValid(byte[] klicensee, string filename)
            => TitleHashValid(filename) && HeaderValid(klicensee);
    }
}
