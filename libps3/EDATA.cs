// Note:
// The algorithms used for this code are largely adapted from make_npdata.
// Licensing for this code may fall under the license of make_npdata.

using Edoke.IO;
using libps3.Compression;
using libps3.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.CompilerServices;

namespace libps3
{
    /// <summary>
    /// An encrypted data container for NPDRM.
    /// </summary>
    public class EDATA : IDisposable
    {
        #region Constants

        /// <summary>
        /// The default <see cref="BlockSize"/>.
        /// </summary>
        public const int DefaultBlockSize = 16384;

        /// <summary>
        /// Packager version "SDATA packager" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata1 = "SDATA packager";

        /// <summary>
        /// Packager version "EDATA packager" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata1 = "EDATA packager";

        /// <summary>
        /// Packager version "SDATA 2.4.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata240L = "SDATA 2.4.0.L";

        /// <summary>
        /// Packager version "EDATA 2.4.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata240L = "EDATA 2.4.0.L";

        /// <summary>
        /// Packager version "SDATA 2.4.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata240W = "SDATA 2.4.0.W";

        /// <summary>
        /// Packager version "EDATA 2.4.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata240W = "EDATA 2.4.0.W";

        /// <summary>
        /// Packager version "SDATA 2.7.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata270L = "SDATA 2.7.0.L";

        /// <summary>
        /// Packager version "EDATA 2.7.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata270L = "EDATA 2.7.0.L";

        /// <summary>
        /// Packager version "SDATA 2.7.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata270W = "SDATA 2.7.0.W";

        /// <summary>
        /// Packager version "EDATA 2.7.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata270W = "EDATA 2.7.0.W";

        /// <summary>
        /// Packager version "SDATA 3.3.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata330L = "SDATA 3.3.0.L";

        /// <summary>
        /// Packager version "EDATA 3.3.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata330L = "EDATA 3.3.0.L";

        /// <summary>
        /// Packager version "SDATA 3.3.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata330W = "SDATA 3.3.0.W";

        /// <summary>
        /// Packager version "EDATA 3.3.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata330W = "EDATA 3.3.0.W";

        /// <summary>
        /// Packager version "SDATA 4.0.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata400L = "SDATA 4.0.0.L";

        /// <summary>
        /// Packager version "EDATA 4.0.0.L" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata400L = "EDATA 4.0.0.L";

        /// <summary>
        /// Packager version "SDATA 4.0.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionSdata400W = "SDATA 4.0.0.W";

        /// <summary>
        /// Packager version "EDATA 4.0.0.W" for the <see cref="Footer"/>.
        /// </summary>
        public const string PackagerVersionEdata400W = "EDATA 4.0.0.W";

        /// <summary>
        /// The default packager version for the <see cref="Footer"/>
        /// </summary>
        public const string DefaultPackagerVersion = PackagerVersionEdata400W;

        /// <summary>
        /// The decryption key size.
        /// </summary>
        private const int KeySize = 16;

        #endregion

        #region EdataFlags

        /// <summary>
        /// The flags of the <see cref="EDATA"/>; It is unclear if the field is intended to be separate bytes.
        /// </summary>
        [Flags]
        public enum EdataFlags : int
        {
            // Last Byte (Metadata Flags?)

            /// <summary>
            /// No flags.
            /// </summary>
            None = 0 << 0,

            /// <summary>
            /// The data is compressed.<br/>
            /// If set, the metadata section size is 32.
            /// </summary>
            Compressed = 1 << 0,

            /// <summary>
            /// The data is plaintext.
            /// </summary>
            Plaintext = 1 << 1,

            /// <summary>
            /// The data is encrypted with AES-CBC-128.
            /// </summary>
            Encrypted = 1 << 2,

            /// <summary>
            /// The key is encrypted.
            /// </summary>
            EncryptedKey = 1 << 3,

            /// <summary>
            /// Unknown.<br/>
            /// The hashing algorithm will be 16-byte AES-CMAC.
            /// </summary>
            UNK_4 = 1 << 4,

            /// <summary>
            /// Unknown.<br/>
            /// If set, the metadata section size is 32.<br/>
            /// The hashing algorithm will be 16-byte SHA1-HMAC.
            /// </summary>
            UNK_5 = 1 << 5,

            // First byte (SDATA/EDATA/Debug type enum?)

            /// <summary>
            /// The data is SDATA and not EDATA.
            /// </summary>
            Sdata = 1 << 30,

            /// <summary>
            /// The data is not finalized.
            /// </summary>
            Debug = 1 << 31
        }

        #endregion

        #region Members

        /// <summary>
        /// The <see cref="libps3.NPD"/> header of this <see cref="EDATA"/>.
        /// </summary>
        public NPD NPD { get; set; }

        /// <summary>
        /// The flags of this <see cref="EDATA"/>, determining various properties such as compression and encryption state.
        /// </summary>
        public EdataFlags Flags { get; set; }

        /// <summary>
        /// The block size used in decryption and encryption.<br/>
        /// Must be set to a valid working size of 1KBs, 2KBs, 4KBs, 8KBs, 16KBs, or 32KBs.
        /// </summary>
        public int BlockSize
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => _BlockSize;
            set
            {
                if (value != 1024 &&
                    value != 2048 &&
                    value != 4096 &&
                    value != 8192 &&
                    value != 16384 &&
                    value != 32768)
                {
                    throw new InvalidDataException($"{nameof(BlockSize)} must be set to a valid working size of 1KBs, 2KBs, 4KBs, 8KBs, 16KBs, or 32KBs.");
                }

                _BlockSize = value;
            }
        }

        /// <summary>
        /// A field for <see cref="BlockSize"/>.
        /// </summary>
        private int _BlockSize;

        /// <summary>
        /// The size of the original data.
        /// </summary>
        private long DataSize { get; set; }

        /// <summary>
        /// The metadata section hash. 
        /// </summary>
        private byte[] MetadataHash { get; set; }

        /// <summary>
        /// An AES-CMAC hash of the first 160 bytes of the file, which are all <see cref="EDATA"/> and <see cref="libps3.NPD"/> bytes above it.
        /// </summary>
        private byte[] ExtendedHeaderHash { get; set; }

        /// <summary>
        /// The ecdsa metadata signature.
        /// </summary>
        private byte[] EcdsaMetadataSignature { get; set; }

        /// <summary>
        /// The ecdsa header signature.
        /// </summary>
        private byte[] EcdsaHeaderSignature { get; set; }

        /// <summary>
        /// The footer, containing the packager version.<br/>
        /// May not be present on <see cref="NPD.Version"/> 1 or homebrew <see cref="EDATA"/> files.
        /// </summary>
        public string Footer
        {
            get => _Footer;
            set
            {
                if (value.Length > 16)
                {
                    throw new InvalidDataException($"{nameof(Footer)} has a maximum of {16} characters.");
                }

                _Footer = value;
            }
        }

        /// <summary>
        /// A field for <see cref="Footer"/>.
        /// </summary>
        private string _Footer = string.Empty;

        /// <summary>
        /// Whether or not the <see cref="Footer"/> is present.<br/>
        /// When writing this will determine whether or not a <see cref="Footer"/> is written.<br/>
        /// Ignored when writing an <see cref="NPD.Version"/> above 1.
        /// </summary>
        public bool HasFooter { get; set; }

        /// <summary>
        /// A <see cref="Stream"/> containing the encrypted data.
        /// </summary>
        private Stream EncryptedData { get; set; }

        /// <summary>
        /// Whether or not this <see cref="EDATA"/> is disposed.
        /// </summary>
        private bool disposedValue;

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new <see cref="EDATA"/> with default values.
        /// </summary>
        public EDATA()
        {
            NPD = new NPD();
            Flags = EdataFlags.None;
            _BlockSize = DefaultBlockSize;
            DataSize = 0;
            MetadataHash = new byte[16];
            ExtendedHeaderHash = new byte[16];
            EcdsaMetadataSignature = new byte[40];
            EcdsaHeaderSignature = new byte[40];
            _Footer = DefaultPackagerVersion;
            HasFooter = true;

            EncryptedData = new MemoryStream();
        }

        /// <summary>
        /// Reads an <see cref="EDATA"/> from a <see cref="Stream"/>.
        /// </summary>
        /// <param name="br">The <see cref="Stream"/> reader.</param>
        private EDATA(BinaryStreamReader br)
        {
            NPD = new NPD(br);
            Flags = (EdataFlags)br.ReadInt32();
            _BlockSize = br.ReadInt32();
            DataSize = br.ReadInt32();
            MetadataHash = br.ReadBytes(16);
            ExtendedHeaderHash = br.ReadBytes(16);
            EcdsaMetadataSignature = br.ReadBytes(40);
            EcdsaHeaderSignature = br.ReadBytes(40);

            // Hacky implementation, need to find better way of detecting this
            long length;
            long probableFooterPos = br.Length - 16;
            byte[] footerBytes = br.GetBytes(probableFooterPos, 16);
            if (TryGetFooter(footerBytes, out string? footer))
            {
                length = probableFooterPos - br.Position;
                _Footer = footer;
                HasFooter = true;
            }
            else
            {
                length = br.Remaining;
                _Footer = string.Empty;
                HasFooter = false;
            }

            // Do not dispose of incoming reader stream
            EncryptedData = new SubStream(br.BaseStream, br.Position, length);
        }

        /// <summary>
        /// Reads an <see cref="EDATA"/> from bytes.
        /// </summary>
        /// <param name="br">The byte reader.</param>
        private EDATA(ref BinarySpanReader br)
        {
            NPD = new NPD(ref br);
            Flags = (EdataFlags)br.ReadInt32();
            _BlockSize = br.ReadInt32();
            DataSize = br.ReadInt64();
            MetadataHash = br.ReadBytes(16);
            ExtendedHeaderHash = br.ReadBytes(16);
            EcdsaMetadataSignature = br.ReadBytes(40);
            EcdsaHeaderSignature = br.ReadBytes(40);

            // Hacky implementation, need to find better way of detecting this
            int length;
            int probableFooterPos = br.Length - 16;
            byte[] footerBytes = br.GetBytes(probableFooterPos, 16);
            if (TryGetFooter(footerBytes, out string? footer))
            {
                length = probableFooterPos - br.Position;
                _Footer = footer;
                HasFooter = true;
            }
            else
            {
                length = br.Remaining;
                _Footer = string.Empty;
                HasFooter = false;
            }

            byte[] bytes = br.ReadBytes(length);
            EncryptedData = new MemoryStream(bytes, false);
        }

        #endregion

        #region Is

        /// <summary>
        /// Whether or not the specified <see cref="Stream"/> appears to be an <see cref="EDATA"/>.
        /// </summary>
        /// <param name="br">The <see cref="Stream"/> reader.</param>
        /// <returns>Whether or not the specified <see cref="Stream"/> appears to be an <see cref="EDATA"/>.</returns>
        private static bool Is(BinaryStreamReader br)
            => NPD.Is(br);

        /// <summary>
        /// Whether or not the specified bytes appear to be an <see cref="EDATA"/>.
        /// </summary>
        /// <param name="br">The byte reader.</param>
        /// <returns>Whether or not the specified bytes appear to be an <see cref="EDATA"/>.</returns>
        private static bool Is(BinarySpanReader br)
            => NPD.Is(br);

        /// <summary>
        /// Whether or not the specified file appears to be an <see cref="EDATA"/>.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>Whether or not the specified file appears to be an <see cref="EDATA"/>.</returns>
        public static bool Is(string path)
        {
            using var br = new BinaryStreamReader(path, true);
            return Is(br);
        }

        /// <summary>
        /// Whether or not the specified bytes appear to be an <see cref="EDATA"/>.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>Whether or not the specified bytes appear to be an <see cref="EDATA"/>.</returns>
        public static bool Is(byte[] bytes)
            => Is(new BinarySpanReader(bytes, true));

        /// <summary>
        /// Whether or not the specified <see cref="Stream"/> appears to be an <see cref="EDATA"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        /// <returns>Whether or not the specified <see cref="Stream"/> appears to be an <see cref="EDATA"/>.</returns>
        public static bool Is(Stream stream)
        {
            using var br = new BinaryStreamReader(stream, true, true);
            return Is(br);
        }

        #endregion

        #region Read

        /// <summary>
        /// Reads an <see cref="EDATA"/> from the specified file.
        /// </summary>
        /// <param name="path">The file path.</param>
        /// <returns>A new <see cref="EDATA"/>.</returns>
        public static EDATA Read(string path)
        {
            using var br = new BinaryStreamReader(path, true);
            return new EDATA(br);
        }

        /// <summary>
        /// Reads an <see cref="EDATA"/> from the specified bytes.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>A new <see cref="EDATA"/>.</returns>
        public static EDATA Read(byte[] bytes)
        {
            var br = new BinarySpanReader(bytes, true);
            return new EDATA(ref br);
        }

        /// <summary>
        /// Reads an <see cref="NPD"/> from a <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        /// <returns>A new <see cref="NPD"/>.</returns>
        public static EDATA Read(Stream stream)
        {
            using var br = new BinaryStreamReader(stream, true, true);
            return new EDATA(br);
        }

        #endregion 

        #region Write

        /// <summary>
        /// Writes this <see cref="EDATA"/> to a <see cref="Stream"/>.
        /// </summary>
        /// <param name="bw">The <see cref="Stream"/> writer.</param>
        internal void Write(BinaryStreamWriter bw)
        {
            NPD.Write(bw);
            bw.WriteInt32((int)Flags);
            bw.WriteInt32(_BlockSize);
            bw.WriteInt64(DataSize);
            bw.WriteBytes(MetadataHash);
            bw.WriteBytes(ExtendedHeaderHash);
            bw.WriteBytes(EcdsaMetadataSignature);
            bw.WriteBytes(EcdsaHeaderSignature);

            EncryptedData.CopyTo(bw.BaseStream);
            if (EncryptedData.CanSeek)
            {
                EncryptedData.Seek(0, SeekOrigin.Begin);
            }

            if (!(!HasFooter && (NPD.Version == 0 || NPD.Version == 1)))
            {
                bw.WriteASCII(Footer, 16);
            }
        }

        /// <summary>
        /// Writes this <see cref="EDATA"/> to a file.
        /// </summary>
        /// <param name="path">The file path.</param>
        public void Write(string path)
        {
            using var bw = new BinaryStreamWriter(path, true);
            Write(bw);
        }

        /// <summary>
        /// Writes this <see cref="EDATA"/> to bytes.
        /// </summary>
        /// <returns>An array of bytes.</returns>
        public byte[] Write()
        {
            using var bw = new BinaryStreamWriter(true);
            Write(bw);
            return bw.FinishBytes();
        }

        /// <summary>
        /// Writes this <see cref="EDATA"/> to a <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">The <see cref="Stream"/>.</param>
        public void Write(Stream stream)
        {
            using var bw = new BinaryStreamWriter(stream, true, true);
            Write(bw);
        }

        #endregion

        #region Decrypt

        private void GetDecryptionKey(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Span<byte> key)
        {
            if (IsSdata())
            {
                // We need to use the SDATA key
                NPD.GetSdataKey(key);
                return;
            }

            // Do validation for EDATA
            if (!NPD.IsValid(filename, klicensee))
            {
                // Validation failed
                throw new InvalidDataException($"{nameof(NPD)} is not valid.");
            }

            if (NPD.IsFree())
            {
                // For free EDATA, return the dev klicensee
                klicensee.CopyTo(key);
                return;
            }

            // For non-free EDATA, return the rif key.
            RAP.RapToRif(rap, key);
        }

        private static void DecryptMetadataSection(Span<byte> metadata, Span<byte> decryptedMetadata)
        {
            decryptedMetadata[0] = (byte)(metadata[12] ^ metadata[8] ^ metadata[16]);
            decryptedMetadata[1] = (byte)(metadata[13] ^ metadata[9] ^ metadata[17]);
            decryptedMetadata[2] = (byte)(metadata[14] ^ metadata[10] ^ metadata[18]);
            decryptedMetadata[3] = (byte)(metadata[15] ^ metadata[11] ^ metadata[19]);
            decryptedMetadata[4] = (byte)(metadata[4] ^ metadata[8] ^ metadata[20]);
            decryptedMetadata[5] = (byte)(metadata[5] ^ metadata[9] ^ metadata[21]);
            decryptedMetadata[6] = (byte)(metadata[6] ^ metadata[10] ^ metadata[22]);
            decryptedMetadata[7] = (byte)(metadata[7] ^ metadata[11] ^ metadata[23]);
            decryptedMetadata[8] = (byte)(metadata[12] ^ metadata[0] ^ metadata[24]);
            decryptedMetadata[9] = (byte)(metadata[13] ^ metadata[1] ^ metadata[25]);
            decryptedMetadata[10] = (byte)(metadata[14] ^ metadata[2] ^ metadata[26]);
            decryptedMetadata[11] = (byte)(metadata[15] ^ metadata[3] ^ metadata[27]);
            decryptedMetadata[12] = (byte)(metadata[4] ^ metadata[0] ^ metadata[28]);
            decryptedMetadata[13] = (byte)(metadata[5] ^ metadata[1] ^ metadata[29]);
            decryptedMetadata[14] = (byte)(metadata[6] ^ metadata[2] ^ metadata[30]);
            decryptedMetadata[15] = (byte)(metadata[7] ^ metadata[3] ^ metadata[31]);
        }

        private void DecryptKeyHash(Span<byte> keyHash)
        {
            if (IsKeyEncrypted())
            {
                var decryptionKey = KeyVault.EDAT_KEY_0;
                if (NPD.Version == 4)
                {
                    decryptionKey = KeyVault.EDAT_KEY_1;
                }

                AesCrypto.DecryptCbc(keyHash, decryptionKey, KeyVault.EDAT_IV);
            }
        }

        private bool DecryptData(Span<byte> key, Span<byte> iv, Span<byte> hashKey, Span<byte> hash, Span<byte> data, bool isEncrypted, bool isUnk4)
        {
            // Decrypt the key and hash
            DecryptKeyHash(key);
            DecryptKeyHash(hashKey);

            // Verify the encrypted data
            bool result;
            if (!isUnk4) // AES-CMAC-128
            {
                result = AesHash.CompareAesCmac(hashKey, data, hash);
            }
            else // SHA1-HMAC 128 or 160
            {
                result = ShaHash.CompareSha1Hmac(hashKey, data, hash);
            }

            // Only try decrypting if validation passed
            if (result)
            {
                // Decrypt the block data
                if (isEncrypted)
                {
                    AesCrypto.DecryptCbc(data, key, iv);
                }
            }

            return result;
        }

        public void Decrypt(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Stream output)
        {
            // Get decryption key
            Span<byte> key = stackalloc byte[KeySize];
            GetDecryptionKey(filename, klicensee, rap, key);

            // Decrypt blocks
            // Check flags
            bool isCompressed = IsCompressed();
            bool isUnk4 = (Flags & EdataFlags.UNK_4) != 0;
            bool isUnk5 = (Flags & EdataFlags.UNK_5) != 0;
            bool isEncrypted = IsEncrypted();
            bool isKeyEncrypted = IsKeyEncrypted();
            bool isDebug = IsDebug();
            bool isPlaintext = IsPlaintext();

            // Calculate sizes
            int numBlocks = (int)((DataSize + BlockSize - 1) / BlockSize);
            int metadataSectionSize = (isCompressed || isUnk5) ? 32 : 16;
            long sizeLeft = DataSize;

            // Setup input and output
            using var br = new BinaryStreamReader(EncryptedData, true, true);
            using var bw = new BinaryStreamWriter(output, true, true);

            // Setup reusable block buffers
            bool isOldNpd = NPD.Version <= 1;
            Span<byte> iv = stackalloc byte[16];
            if (!isOldNpd) // NPD versions 1 and below have an empty IV
                NPD.Digest.CopyTo(iv);

            Span<byte> blockKey = stackalloc byte[16];
            Span<byte> encBlockKey = stackalloc byte[16];
            Span<byte> hashKey = stackalloc byte[16];
            Span<byte> hash = stackalloc byte[20];
            Span<byte> metadata = stackalloc byte[32];
            Span<byte> decryptedMetadata = stackalloc byte[16];
            var mbr = new BinarySpanReader(decryptedMetadata);
            for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++)
            {
                // Decrypt metadata
                long offset;
                int length;
                int compressionEnd;
                if (isCompressed)
                {
                    // Go to metadata
                    br.Position = (long)blockIndex * metadataSectionSize;

                    // Read the 32 bytes of metadata
                    br.ReadBytes(metadata);

                    // Get hash from first 16 bytes of metadata
                    for (int i = 0; i < 16; i++)
                        hash[i] = metadata[i];

                    // Decrypt last 16 bytes of metadata
                    if (isOldNpd)
                    {
                        // Metadata section is not encrypted for version 1
                        for (int i = 0; i < 16; i++)
                            decryptedMetadata[i] = metadata[i + 16];
                    }
                    else
                    {
                        DecryptMetadataSection(metadata, decryptedMetadata);
                    }

                    // Read last 16 bytes of decrypted metadata
                    mbr.Position = 0;
                    offset = mbr.ReadInt64();
                    length = mbr.ReadInt32();
                    compressionEnd = mbr.ReadInt32();
                }
                else if (isUnk5)
                {
                    // Go to metadata
                    // Metadata is before each data block if flag 5 is set
                    br.Position = (long)blockIndex * (metadataSectionSize + BlockSize);

                    // Read the 32 bytes of metadata
                    br.ReadBytes(metadata);

                    // Get hash from first 20 bytes of metadata
                    for (int i = 0; i < 20; i++)
                        hash[i] = metadata[i];

                    // Apply custom XOR to first 16 bytes of hash if flag 5 is set
                    for (int i = 0; i < 16; i++)
                        hash[i] = (byte)(metadata[i] ^ metadata[i + 16]);

                    // Set the offset and length
                    offset = br.Position;
                    length = BlockSize;
                    compressionEnd = 0; // No compression

                    // If we are on the last block and it is not perfectly fit to a blocksize, use it's remaining length as the length.
                    bool isLastBlock = blockIndex == numBlocks - 1;
                    int blocksRemainder = (int)(DataSize % BlockSize);
                    if (isLastBlock && blocksRemainder > 0)
                        length = blocksRemainder;
                }
                else
                {
                    // Go to metadata
                    br.Position = (long)blockIndex * metadataSectionSize;

                    // Read the first 16 bytes for the metadata hash
                    hash = hash[..16];
                    br.ReadBytes(hash);

                    // Set the offset and length
                    offset = (blockIndex * BlockSize) + ((long)numBlocks * metadataSectionSize);
                    length = BlockSize;
                    compressionEnd = 0; // No compression

                    // If we are on the last block and it is not perfectly fit to a blocksize, use it's remaining length as the length.
                    bool isLastBlock = blockIndex == numBlocks - 1;
                    int blocksRemainder = (int)(DataSize % BlockSize);
                    if (isLastBlock && blocksRemainder > 0)
                        length = blocksRemainder;
                }

                // Decrypt Block Data
                // Get unpadded length
                int paddedLength = length;
                length = (paddedLength + 15) & -16;

                // Read the unpadded encrypted data
                br.Position = offset;
                Span<byte> data = br.ReadBytes(length);

                // Get the block key
                NPD.GetBlockKey(blockIndex, blockKey);

                // Encrypt the block key
                AesCrypto.EncryptEcb(blockKey, key, encBlockKey);

                // Get the hash or hash key
                if (isUnk4)
                    AesCrypto.EncryptEcb(encBlockKey, key, hashKey); // Encrypt again if flag 4 is set
                else
                    encBlockKey.CopyTo(hashKey); // Use the encrypted block key as the hash

                // Decrypt in-place if necessary
                if (!isDebug)
                {
                    if (!DecryptData(encBlockKey, iv, hashKey, hash, data, isEncrypted, isUnk4))
                    {
                        throw new Exception($"Decryption of block {blockIndex} failed.");
                    }
                }

                // Decompress the block data if necessary
                // Then write the block data
                if (isCompressed && compressionEnd > 0)
                {
                    int decompressResult = Lz.Decompress(output, data, (uint)BlockSize);
                    sizeLeft -= decompressResult;
                    if (sizeLeft == 0 && decompressResult < 0)
                    {
                        throw new Exception($"Decompression of block {blockIndex} failed.");
                    }
                }
                else
                {
                    output.Write(data[..paddedLength]);
                }
            }
        }

        #endregion

        #region Encrypt

        public void Encrypt(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Stream input)
        {
            throw new NotImplementedException("Encryption is not yet implemented.");
        }

        #endregion

        #region Read Helpers

        private static bool TryGetFooter(byte[] footerBytes, [NotNullWhen(true)] out string? footer)
        {
            var br = new BinarySpanReader(footerBytes);
            footer = br.ReadASCII();

            const StringComparison strComp = StringComparison.InvariantCultureIgnoreCase;
            if (footer.StartsWith("EDATA", strComp) || footer.StartsWith("SDATA", strComp))
            {
                return true;
            }
            else
            {
                // There are only null bytes to check if we used the full 16 byte space
                if (footer.Length < footerBytes.Length)
                {
                    for (int i = footer.Length; i < footerBytes.Length; i++)
                    {
                        if (footerBytes[i] != 0)
                        {
                            // Detected something after null termination.
                            return false;
                        }
                    }

                    return true;
                }

                Debug.Assert(footerBytes.Length == 16 && footer.Length == 16);

                // Do a best effort english keyboard common character test
                const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 `~!@#$%^&*()-_=+[]{}\\|;:'\",.<>/?\t\r\n";
                foreach (char c in footer)
                {
                    if (!alphabet.Contains(c, strComp))
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        #endregion

        #region Flag Helpers

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsSdata()
            => (Flags & EdataFlags.Sdata) != 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsDebug()
            => (Flags & EdataFlags.Debug) != 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsCompressed()
            => (Flags & EdataFlags.Compressed) != 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsPlaintext()
            => (Flags & EdataFlags.Plaintext) != 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsEncrypted()
            => (Flags & EdataFlags.Encrypted) != 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool IsKeyEncrypted()
            => (Flags & EdataFlags.EncryptedKey) != 0;

        #endregion

        #region Footer Helpers

        public string GetPackagerVersionFromNpd()
        {
            bool isSdata = IsSdata();
            switch (NPD.Version)
            {
                case 0: // Just in case
                case 1:
                    return isSdata ? PackagerVersionSdata1 : PackagerVersionEdata1;
                case 2:
                    return isSdata ? PackagerVersionSdata270W : PackagerVersionEdata270W;
                case 3:
                    return isSdata ? PackagerVersionSdata330W : PackagerVersionEdata330W;
                case 4:
                default:
                    return isSdata ? PackagerVersionSdata400W : PackagerVersionEdata400W;
            }
        }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    EncryptedData.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
