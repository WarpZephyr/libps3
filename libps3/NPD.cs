using Edoke.IO;
using libps3.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace libps3
{
    /// <summary>
    /// A packet format used in NPDRM.
    /// </summary>
    public class NPD
    {
        #region Constants

        /// <summary>
        /// Packager version 1 for <see cref="Version"/>.
        /// </summary>
        public const int PackagerVersion1 = 1;

        /// <summary>
        /// Packager version 2 for <see cref="Version"/>.
        /// </summary>
        public const int PackagerVersion2 = 2;

        /// <summary>
        /// Packager version 3 for <see cref="Version"/>.
        /// </summary>
        public const int PackagerVersion3 = 3;

        /// <summary>
        /// Packager version 4 for <see cref="Version"/>.
        /// </summary>
        public const int PackagerVersion4 = 4;

        /// <summary>
        /// The default packager version for <see cref="Version"/>.
        /// </summary>
        public const int DefaultVersion = PackagerVersion4;

        /// <summary>
        /// The preferred length of the <see cref="ContentId"/>.
        /// </summary>
        public const int PreferredContentIdSize = 36;

        /// <summary>
        /// The max length of the <see cref="ContentId"/>.
        /// </summary>
        public const int ContentIdSize = 48;

        /// <summary>
        /// The length of the <see cref="Digest"/>.
        /// </summary>
        public const int DigestSize = 16;

        /// <summary>
        /// The length of the <see cref="TitleHash"/>.
        /// </summary>
        private const int TitleHashSize = 16;

        /// <summary>
        /// The length of the <see cref="HeaderHash"/>.
        /// </summary>
        private const int HeaderHashSize = 16;

        /// <summary>
        /// The length of a klicensee.
        /// </summary>
        private const int KlicenseeSize = 16;

        /// <summary>
        /// The length of a block key.
        /// </summary>
        private const int BlockKeySize = 16;

        /// <summary>
        /// The size of the header bytes hashed for <see cref="HeaderHash"/>.
        /// </summary>
        private const int HeaderBytesSize = 96;

        /// <summary>
        /// The maximum size of a filename on the PS3.
        /// </summary>
        private const int FileNameMaxSize = 1055;

        #endregion

        #region DrmType

        public enum DrmType : int
        {
            Unknown = 0, // Official name
            Network = 1,
            Local = 2,
            Free = 3,
            PSP = 4,
            Free_PSP2_PSM = 0xD,
            Network_PSP_PSP2 = 0x100,
            GameCard = 0x400,
            Unknown_PS3 = 0x2000
        }

        #endregion

        #region AppType

        public enum AppType : int
        {
            Module = 0,
            Executable = 1,
            Unknown_16 = 0x10,
            Module_Disc_Update = 0x20,
            Executable_Disc_Update = 0x21,
            Module_HDD_Update = 0x30,
            Executable_HDD_Update = 0x31
        }

        #endregion

        #region Members

        /// <summary>
        /// The <see cref="NPD"/> packager version.
        /// </summary>
        public int Version { get; set; }

        /// <summary>
        /// The applied DRM.
        /// </summary>
        public DrmType License { get; set; }

        /// <summary>
        /// The type of application contained within the <see cref="NPD"/>.
        /// </summary>
        public AppType App { get; set; }

        /// <summary>
        /// The content id of the <see cref="NPD"/>, also the name of the rap file for it without extension if applicable.
        /// </summary>
        public string ContentId
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => _ContentId;
            set
            {
                if (value.Length != ContentIdSize)
                {
                    throw new InvalidOperationException($"{nameof(ContentId)} must be {ContentIdSize} bytes in length.");
                }

                _ContentId = value;
            }
        }

        /// <summary>
        /// A field for <see cref="ContentId"/>.
        /// </summary>
        private string _ContentId;

        /// <summary>
        /// A QA digest, which may be arbitrary.
        /// </summary>
        public byte[] Digest
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => _Digest;
            set
            {
                if (value.Length != DigestSize)
                {
                    throw new InvalidOperationException($"{nameof(Digest)} must be {DigestSize} bytes in length.");
                }

                _Digest = value;
            }
        }

        /// <summary>
        /// A field for <see cref="Digest"/>.
        /// </summary>
        private byte[] _Digest;

        /// <summary>
        /// A hash of the full 48-byte <see cref="ContentId"/> combined with the EDAT, SDAT, or SELF filename.
        /// </summary>
        private byte[] TitleHash { get; set; }

        /// <summary>
        /// A hash of the first 96 bytes, which are all <see cref="NPD"/> bytes above it.
        /// </summary>
        private byte[] HeaderHash { get; set; }

        /// <summary>
        /// The date time the content contained within becomes available in milliseconds.
        /// </summary>
        public ulong ActivateTime { get; set; }

        /// <summary>
        /// The date time the content within expires in milliseconds.
        /// </summary>
        public ulong ExpireTime { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new <see cref="NPD"/> with default values.
        /// </summary>
        public NPD()
        {
            Version = DefaultVersion;
            License = DrmType.Free;
            App = AppType.Module;
            _ContentId = "XXXXXX-XXXXXXXXX_XX-XXXXXXXXXXXXXXXX";
            _Digest = new byte[DigestSize];
            TitleHash = new byte[TitleHashSize];
            HeaderHash = new byte[HeaderHashSize];
        }

        /// <summary>
        /// Reads an <see cref="NPD"/> from a <see cref="Stream"/>.
        /// </summary>
        /// <param name="br">The <see cref="Stream"/> reader.</param>
        internal NPD(BinaryStreamReader br)
        {
            br.AssertASCII("NPD\0");
            Version = br.ReadInt32();
            License = br.ReadEnumInt32<DrmType>();
            App = br.ReadEnumInt32<AppType>();
            _ContentId = br.ReadASCII(ContentIdSize, true);
            _Digest = br.ReadBytes(DigestSize);
            TitleHash = br.ReadBytes(TitleHashSize);
            HeaderHash = br.ReadBytes(HeaderHashSize);
            ActivateTime = br.ReadUInt64();
            ExpireTime = br.ReadUInt64();
        }

        /// <summary>
        /// Reads an <see cref="NPD"/> from bytes.
        /// </summary>
        /// <param name="br">The byte reader.</param>
        internal NPD(ref BinarySpanReader br)
        {
            br.AssertASCII("NPD\0");
            Version = br.ReadInt32();
            License = br.ReadEnumInt32<DrmType>();
            App = br.ReadEnumInt32<AppType>();
            _ContentId = br.ReadASCII(ContentIdSize, true);
            _Digest = br.ReadBytes(DigestSize);
            TitleHash = br.ReadBytes(TitleHashSize);
            HeaderHash = br.ReadBytes(HeaderHashSize);
            ActivateTime = br.ReadUInt64();
            ExpireTime = br.ReadUInt64();
        }

        #endregion

        #region Is

        /// <summary>
        /// Whether or not the specified <see cref="Stream"/> appears to be an <see cref="NPD"/>.
        /// </summary>
        /// <param name="br">The <see cref="Stream"/> reader.</param>
        /// <returns>Whether or not the specified <see cref="Stream"/> appears to be an <see cref="NPD"/>.</returns>
        internal static bool Is(BinaryStreamReader br)
            => br.GetASCII(0, 4) == "NPD\0";

        /// <summary>
        /// Whether or not the specified bytes appear to be an <see cref="NPD"/>.
        /// </summary>
        /// <param name="br">The byte reader.</param>
        /// <returns>Whether or not the specified bytes appear to be an <see cref="NPD"/>.</returns>
        internal static bool Is(BinarySpanReader br)
            => br.GetASCII(0, 4) == "NPD\0";

        /// <summary>
        /// Whether or not the specified file appears to be an <see cref="NPD"/>.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>Whether or not the specified file appears to be an <see cref="NPD"/>.</returns>
        public static bool Is(string path)
        {
            using var br = new BinaryStreamReader(path, true);
            return Is(br);
        }

        /// <summary>
        /// Whether or not the specified bytes appear to be an <see cref="NPD"/>.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>Whether or not the specified bytes appear to be an <see cref="NPD"/>.</returns>
        public static bool Is(byte[] bytes)
            => Is(new BinarySpanReader(bytes, true));

        /// <summary>
        /// Whether or not the specified <see cref="Stream"/> appears to be an <see cref="NPD"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        /// <returns>Whether or not the specified <see cref="Stream"/> appears to be an <see cref="NPD"/>.</returns>
        public static bool Is(Stream stream)
        {
            using var br = new BinaryStreamReader(stream, true, true);
            return Is(br);
        }

        #endregion

        #region Read

        /// <summary>
        /// Reads an <see cref="NPD"/> from the specified bytes.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>A new <see cref="NPD"/>.</returns>
        public static NPD Read(byte[] bytes)
        {
            var br = new BinarySpanReader(bytes, true);
            return new NPD(ref br);
        }

        /// <summary>
        /// Reads an <see cref="NPD"/> from a <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        /// <returns>A new <see cref="NPD"/>.</returns>
        public static NPD Read(Stream stream)
        {
            using var br = new BinaryStreamReader(stream, true, true);
            return new NPD(br);
        }

        #endregion

        #region Write

        /// <summary>
        /// Writes this <see cref="NPD"/> to a <see cref="Stream"/>.
        /// </summary>
        /// <param name="bw">The <see cref="Stream"/> writer.</param>
        internal void Write(BinaryStreamWriter bw)
        {
            bw.WriteASCII("NPD\0", false);
            bw.WriteInt32(Version);
            bw.WriteInt32((int)License);
            bw.WriteInt32((int)App);
            bw.WriteASCII(_ContentId, 48);
            bw.WriteBytes(_Digest);
            bw.WriteBytes(TitleHash);
            bw.WriteBytes(HeaderHash);
            bw.WriteUInt64(ActivateTime);
            bw.WriteUInt64(ExpireTime);
        }

        /// <summary>
        /// Writes this <see cref="NPD"/> to bytes.
        /// </summary>
        /// <param name="bw">The byte writer.</param>
        internal void Write(ref BinarySpanWriter bw)
        {
            bw.WriteASCII("NPD\0", false);
            bw.WriteInt32(Version);
            bw.WriteInt32((int)License);
            bw.WriteInt32((int)App);
            bw.WriteASCII(_ContentId, 48);
            bw.WriteBytes(_Digest);
            bw.WriteBytes(TitleHash);
            bw.WriteBytes(HeaderHash);
            bw.WriteUInt64(ActivateTime);
            bw.WriteUInt64(ExpireTime);
        }

        /// <summary>
        /// Writes this <see cref="NPD"/> to bytes.
        /// </summary>
        /// <returns>An array of bytes.</returns>
        public byte[] Write()
        {
            byte[] bytes = new byte[128];
            var bw = new BinarySpanWriter(bytes, true);
            Write(ref bw);
            return bytes;
        }

        /// <summary>
        /// Writes this <see cref="NPD"/> to a <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        public void Write(Stream stream)
        {
            using var bw = new BinaryStreamWriter(stream, true, true);
            Write(bw);
        }

        #endregion

        #region Decryption

        internal void GetSdataKey(Span<byte> output)
        {
            Debug.Assert(output.Length >= HeaderHashSize, $"The output buffer should be at least {HeaderHashSize} in length.");
            ByteOperation.Xor(HeaderHash, KeyVault.SDAT_KEY, output);
        }

        /// <summary>
        /// Calculates a key required to decrypt the specified block.
        /// </summary>
        /// <param name="blockIndex">The index of the block to decrypt.</param>
        /// <param name="output">The output buffer for the block key.</param>
        internal void GetBlockKey(int blockIndex, Span<byte> output)
        {
            Debug.Assert(output.Length >= BlockKeySize, $"The output buffer should be at least {BlockKeySize} in length.");

            if (Version <= 1)
            {
                // When version is 1 the first 12 bytes of the block key are 0
                for (int i = 0; i < 12; i++)
                    output[i] = 0;
            }
            else
            {
                // The first 12 bytes of the block key are the first 12 bytes of the header hash
                for (int i = 0; i < 12; i++)
                    output[i] = HeaderHash[i];
            }

            // The last 4 bytes of the block key are the block index
            var br = new BinarySpanWriter(output, true)
            {
                Position = 12
            };

            br.WriteInt32(blockIndex);
        }

        #endregion

        #region Drm Helpers

        /// <summary>
        /// Whether or not the <see cref="License"/> is free.
        /// </summary>
        /// <returns>Whether or not the <see cref="License"/> is free.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsFree()
            => License == DrmType.Free || License == DrmType.Free_PSP2_PSM;

        #endregion

        #region Validation

        /// <summary>
        /// Write the <see cref="NPD"/> header bytes.
        /// </summary>
        /// <param name="output">The buffer to output the header bytes into.</param>
        private void WriteHeaderBytes(Span<byte> output)
        {
            var bw = new BinarySpanWriter(output, true);
            bw.WriteASCII("NPD\0", 4, 0);
            bw.WriteInt32(Version);
            bw.WriteInt32((int)License);
            bw.WriteInt32((int)App);
            bw.WriteASCII(_ContentId, ContentIdSize);
            bw.WriteBytes(_Digest);
            bw.WriteBytes(TitleHash);
        }

        /// <summary>
        /// Creates a title hash of the <see cref="NPD"/>.
        /// </summary>
        /// <param name="filename">The file name to use in the hash.</param>
        /// <returns>The title hash bytes.</returns>
        private void HashTitle(ReadOnlySpan<char> filename, Span<byte> output)
        {
            // This is to prevent a stack overflow from users passing in massive file names.
            // The limit was decided based on the maximum length a filename can be on the PS3.
            // This limit can be ignored if we heap allocate the hashable content instead, but stack allocation would be nicer to have.
            if (filename.Length > FileNameMaxSize)
                throw new ArgumentOutOfRangeException(nameof(filename), $"{nameof(filename)} is too long, it should not exceed {FileNameMaxSize} characters.");

            // Get the hashable content
            Span<byte> contentBytes = stackalloc byte[ContentIdSize + filename.Length];
            int written = Encoding.ASCII.GetBytes(_ContentId, contentBytes);
            if (written != _ContentId.Length)
                throw new Exception($"Failed to write {nameof(ContentId)} to title hashable buffer.");

            written = Encoding.ASCII.GetBytes(filename, contentBytes[ContentIdSize..]);
            if (written != filename.Length)
                throw new Exception($"Failed to write {nameof(filename)} to title hashable buffer.");

            // Compute AES-CMAC
            AesHash.ComputeAesCmac(KeyVault.NP_TITLE_OMAC_KEY, contentBytes, output);
        }

        /// <summary>
        /// Creates a header hash of the <see cref="NPD"/>.
        /// </summary>
        /// <param name="klicensee">The klicensee bytes to use in the hash.</param>
        /// <returns>The header hash bytes.</returns>
        private void HashHeader(ReadOnlySpan<byte> klicensee, Span<byte> output)
        {
            // Get XOR key
            Span<byte> key = stackalloc byte[KlicenseeSize];
            ByteOperation.Xor(klicensee, KeyVault.NP_HEADER_OMAC_KEY, key);

            // Get header bytes
            Span<byte> headerBytes = stackalloc byte[HeaderBytesSize];
            WriteHeaderBytes(headerBytes);

            // Compute AES-CMAC
            AesHash.ComputeAesCmac(key, headerBytes, output);
        }

        /// <summary>
        /// Whether or not the content id and file name are valid.
        /// </summary>
        /// <param name="filename">The EDAT file name with the edat extension.</param>
        /// <returns>Whether or not the content id and file name are valid.</returns>
        public bool IsTitleValid(ReadOnlySpan<char> filename)
        {
            Span<byte> hashBuffer = stackalloc byte[TitleHashSize];
            HashTitle(filename, hashBuffer);
            return hashBuffer.SequenceEqual(TitleHash);
        }

        /// <summary>
        /// Whether or not the current header is valid.
        /// </summary>
        /// <param name="klicensee">The klicensee for the <see cref="NPD"/>.</param>
        /// <returns>Whether or not the current header is valid.</returns>
        public bool IsHeaderValid(ReadOnlySpan<byte> klicensee)
        {
            // Check parameters
            if (klicensee.Length < KlicenseeSize)
                throw new ArgumentOutOfRangeException(nameof(klicensee), $"{nameof(klicensee)} should be at least {KlicenseeSize} bytes in length.");

            Span<byte> hashBuffer = stackalloc byte[HeaderHashSize];
            HashHeader(klicensee, hashBuffer);
            return hashBuffer.SequenceEqual(HeaderHash);
        }

        /// <summary>
        /// Whether or not the current <see cref="NPD"/> is deemed valid.
        /// </summary>
        /// <param name="filename">The EDAT file name with the edat extension.</param>
        /// <param name="klicensee">The klicensee for the <see cref="NPD"/>.</param>
        /// <returns>Whether or not the current <see cref="NPD"/> is deemed valid.</returns>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsValid(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee)
            => IsTitleValid(filename) && IsHeaderValid(klicensee);

        /// <summary>
        /// Updates the validity of the content id, file name, and header.
        /// </summary>
        /// <param name="filename">The EDAT file name with the edat extension.</param>
        /// <param name="klicensee">The klicensee for the <see cref="NPD"/>.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Update(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee)
        {
            HashTitle(filename, TitleHash);
            HashHeader(klicensee, HeaderHash);
        }

        #endregion
    }
}
