// Note:
// The algorithms used for this code are largely adapted from make_npdata.
// Licensing for this code may fall under the license of make_npdata.

using Edoke.IO;
using libps3.Compression;
using libps3.Cryptography;
using libps3.Helpers;
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
        /// The default flags for version 1.
        /// </summary>
        public const EdataFlags DefaultFlags1 = EdataFlags.None;

        /// <summary>
        /// The default flags for version 2.
        /// </summary>
        public const EdataFlags DefaultFlags2 = EdataFlags.UNK_2 | EdataFlags.EncryptedKey;

        /// <summary>
        /// The default flags for version 3.
        /// </summary>
        public const EdataFlags DefaultFlags3 = DefaultFlags2 | EdataFlags.UNK_4 | EdataFlags.UNK_5;

        /// <summary>
        /// The default flags for version 4.
        /// </summary>
        public const EdataFlags DefaultFlags4 = DefaultFlags3;

        /// <summary>
        /// The possible flags for version 1, including mutually exclusive ones.
        /// </summary>
        private const EdataFlags PossibleFlags1 = DefaultFlags1 | EdataFlags.Compressed | EdataFlags.Debug;

        /// <summary>
        /// The possible flags for version 2, including mutually exclusive ones.
        /// </summary>
        private const EdataFlags PossibleFlags2 = DefaultFlags2 | EdataFlags.Compressed | EdataFlags.Plaintext | EdataFlags.Sdata | EdataFlags.Debug;

        /// <summary>
        /// The possible flags for version 3, including mutually exclusive ones.
        /// </summary>
        private const EdataFlags PossibleFlags3 = DefaultFlags3 | EdataFlags.Compressed | EdataFlags.Plaintext | EdataFlags.Sdata | EdataFlags.Debug;

        /// <summary>
        /// The possible flags for version 4, including mutually exclusive ones.
        /// </summary>
        private const EdataFlags PossibleFlags4 = PossibleFlags3;

        /// <summary>
        /// The decryption key size.
        /// </summary>
        private const int KeySize = 16;

        /// <summary>
        /// The size of the entire EDATA header.
        /// </summary>
        private const int EdataHeaderSize = 256;

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
            /// Unknown.
            /// </summary>
            UNK_2 = 1 << 2,

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
            Sdata = 1 << 24,

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
        private string _Footer;

        /// <summary>
        /// Whether or not the <see cref="Footer"/> is present.<br/>
        /// When writing this will determine whether or not a <see cref="Footer"/> is written.<br/>
        /// Ignored when writing an <see cref="NPD.Version"/> above 1.
        /// </summary>
        public bool HasFooter { get; set; }

        /// <summary>
        /// A <see cref="Stream"/> containing the encrypted data.
        /// </summary>
        private Stream Data;

        /// <summary>
        /// Whether or not this <see cref="EDATA"/> is disposed.
        /// </summary>
        private bool disposedValue;

        #endregion

        #region Properties

        /// <summary>
        /// Data size is greater than the maximum size of arrays.
        /// </summary>
        public bool IsLargeData
            => DataSize > int.MaxValue;

        #endregion

        #region Constructors

        /// <summary>
        /// Creates a new <see cref="EDATA"/> with default values.
        /// </summary>
        public EDATA()
        {
            NPD = new NPD();
            Flags = DefaultFlags4;
            _BlockSize = DefaultBlockSize;
            DataSize = 0;
            MetadataHash = new byte[16];
            ExtendedHeaderHash = new byte[16];
            EcdsaMetadataSignature = new byte[40];
            EcdsaHeaderSignature = new byte[40];
            _Footer = DefaultPackagerVersion;
            HasFooter = true;

            Data = new MemoryStream();
        }

        /// <summary>
        /// Reads an <see cref="EDATA"/> from a <see cref="Stream"/>.
        /// </summary>
        /// <param name="br">The <see cref="Stream"/> reader.</param>
        /// <param name="leaveOpen">Whether or not to leave the underlying data stream open when disposing.</param>
        private EDATA(BinaryStreamReader br, bool leaveOpen)
        {
            NPD = new NPD(br);
            Flags = (EdataFlags)br.ReadInt32();
            CheckFlags();

            _BlockSize = br.ReadInt32();
            DataSize = br.ReadInt64();
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

            Data = new SubStream(br.BaseStream, br.Position, length, leaveOpen);
        }

        /// <summary>
        /// Reads an <see cref="EDATA"/> from bytes.
        /// </summary>
        /// <param name="br">The byte reader.</param>
        private EDATA(ref BinarySpanReader br)
        {
            NPD = new NPD(ref br);
            Flags = (EdataFlags)br.ReadInt32();
            CheckFlags();

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
            Data = new MemoryStream(bytes, false);
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
            var fs = File.OpenRead(path);
            using var br = new BinaryStreamReader(fs, true, true);
            return new EDATA(br, false);
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
            return new EDATA(br, true);
        }

        #endregion 

        #region Write

        /// <summary>
        /// Writes this <see cref="EDATA"/> to a <see cref="Stream"/>.
        /// </summary>
        /// <param name="bw">The <see cref="Stream"/> writer.</param>
        internal void Write(BinaryStreamWriter bw)
        {
            NPD.Write(bw, IsDebug());
            bw.WriteInt32((int)Flags);
            bw.WriteInt32(_BlockSize);
            bw.WriteInt64(DataSize);
            bw.WriteBytes(MetadataHash);
            bw.WriteBytes(ExtendedHeaderHash);
            bw.WriteBytes(EcdsaMetadataSignature);
            bw.WriteBytes(EcdsaHeaderSignature);

            if (Data.Position != 0)
            {
                if (!Data.CanSeek)
                {
                    throw new Exception("Cannot seek encrypted data back to start.");
                }

                Data.Seek(0, SeekOrigin.Begin);
            }

            Data.CopyTo(bw.BaseStream);
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

        #region Crypto

        /// <summary>
        /// Calculates a decryption key for an SDATA file.
        /// </summary>
        /// <param name="output"></param>
        private void GetSdataKey(Span<byte> output)
            => ByteOperation.Xor(NPD.HeaderHash, KeyVault.SDAT_KEY, output, KeySize);

        /// <summary>
        /// Calculates a key required to decrypt the specified block.
        /// </summary>
        /// <param name="blockIndex">The index of the block to decrypt.</param>
        /// <param name="output">The output buffer for the block key.</param>
        private void GetBlockKey(int blockIndex, Span<byte> output)
        {
            if (NPD.Version <= 1)
            {
                // When version is 1 the first 12 bytes of the block key are 0
                for (int i = 0; i < 12; i++)
                    output[i] = 0;
            }
            else
            {
                // The first 12 bytes of the block key are the first 12 bytes of the header hash
                for (int i = 0; i < 12; i++)
                    output[i] = NPD.HeaderHash[i];
            }

            // The last 4 bytes of the block key are the block index
            var br = new BinarySpanWriter(output, true)
            {
                Position = 12
            };

            br.WriteInt32(blockIndex);
        }

        private void GetCryptoKey(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Span<byte> key)
        {
            if (IsSdata())
            {
                // We need to use the SDATA key
                GetSdataKey(key);
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

            // For non-free EDATA, return the rif key
            RAP.RapToRif(rap, key);
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypts a metadata section.
        /// </summary>
        /// <param name="source">The metadata to decrypt or encrypt.</param>
        /// <param name="destination">An output for the decrypted or encrypted metadata.</param>
        private static void DecryptMetadataSection(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            destination[0] = (byte)(source[12] ^ source[8] ^ source[16]);
            destination[1] = (byte)(source[13] ^ source[9] ^ source[17]);
            destination[2] = (byte)(source[14] ^ source[10] ^ source[18]);
            destination[3] = (byte)(source[15] ^ source[11] ^ source[19]);
            destination[4] = (byte)(source[4] ^ source[8] ^ source[20]);
            destination[5] = (byte)(source[5] ^ source[9] ^ source[21]);
            destination[6] = (byte)(source[6] ^ source[10] ^ source[22]);
            destination[7] = (byte)(source[7] ^ source[11] ^ source[23]);
            destination[8] = (byte)(source[12] ^ source[0] ^ source[24]);
            destination[9] = (byte)(source[13] ^ source[1] ^ source[25]);
            destination[10] = (byte)(source[14] ^ source[2] ^ source[26]);
            destination[11] = (byte)(source[15] ^ source[3] ^ source[27]);
            destination[12] = (byte)(source[4] ^ source[0] ^ source[28]);
            destination[13] = (byte)(source[5] ^ source[1] ^ source[29]);
            destination[14] = (byte)(source[6] ^ source[2] ^ source[30]);
            destination[15] = (byte)(source[7] ^ source[3] ^ source[31]);
        }

        /// <summary>
        /// Decrypts either a key or a hash.
        /// </summary>
        /// <param name="keyHash">The key or hash to decrypt.</param>
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

        /// <summary>
        /// Decrypts the specified data with the specified parameters.
        /// </summary>
        /// <param name="key">The key to decrypt with.</param>
        /// <param name="iv">The IV to decrypt with.</param>
        /// <param name="hashKey">The key to decrypt the hash with.</param>
        /// <param name="hash">The hash to test the data integrity.</param>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="isPlaintext">Whether or not the data is plaintext.</param>
        /// <param name="isUnk4">Whether or not the <see cref="EdataFlags.UNK_4"/> flag was set.</param>
        /// <returns>The result of the hash check.</returns>
        private bool DecryptData(Span<byte> key, Span<byte> iv, Span<byte> hashKey, Span<byte> hash, Span<byte> data, bool isPlaintext, bool isUnk4)
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
                if (!isPlaintext)
                {
                    AesCrypto.DecryptCbc(data, key, iv);
                }
            }

            return result;
        }

        /// <summary>
        /// Decrypts the content within the <see cref="EDATA"/> to the output <see cref="Stream"/>.<br/>
        /// If the NPD or EDATA properties are modified before calling decrypt, invalid state may cause errors to occur.<br/>
        /// Decrypting does not modify the underlying data.
        /// </summary>
        /// <param name="filename">The file name of the content.</param>
        /// <param name="klicensee">The dev klicensee of the content.</param>
        /// <param name="rap">The rap key of the content.</param>
        /// <param name="output">The <see cref="Stream"/> to output decrypted content to.</param>
        /// <exception cref="Exception">Decryption failed.</exception>
        public void Decrypt(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Stream output)
        {
            // Check for invalid state
            CheckFlags();

            // Get decryption key
            Span<byte> key = stackalloc byte[KeySize];
            GetCryptoKey(filename, klicensee, rap, key);

            // Decrypt blocks
            // Check flags
            bool isDebug = IsDebug();
            bool isCompressed = IsCompressed();
            bool isPlaintext = IsPlaintext();
            bool isUnk2 = (Flags & EdataFlags.UNK_2) != 0;
            bool isKeyEncrypted = IsKeyEncrypted();
            bool isUnk4 = (Flags & EdataFlags.UNK_4) != 0;
            bool isUnk5 = (Flags & EdataFlags.UNK_5) != 0;

            // Calculate sizes
            int numBlocks = (int)((DataSize + BlockSize - 1) / BlockSize);
            int metadataSectionSize = (isCompressed || isUnk5) ? 32 : 16;
            long sizeLeft = DataSize;

            // Setup input
            using var br = new BinaryStreamReader(Data, true, true);

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
            var mbr = new BinarySpanReader(decryptedMetadata, true);
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
                    // Metadata is before each data block
                    br.Position = (long)blockIndex * (metadataSectionSize + BlockSize);

                    // Read the 32 bytes of metadata
                    br.ReadBytes(metadata);

                    // Get hash from first 20 bytes of metadata
                    for (int i = 0; i < 20; i++)
                        hash[i] = metadata[i];

                    // Apply custom XOR to first 16 bytes of hash
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
                int blockLength = length;
                length = (blockLength + 15) & -16; // We need to pad to the nearest 16 byte fixed AES block.

                // Read the encrypted data
                br.Position = offset;
                Span<byte> data = br.ReadBytes(length);

                // Get the block key
                GetBlockKey(blockIndex, blockKey);

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
                    if (!DecryptData(encBlockKey, iv, hashKey, hash, data, isPlaintext, isUnk4))
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
                    output.Write(data[..blockLength]);
                }
            }
        }

        public byte[] Decrypt(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap)
        {
            if (IsLargeData)
            {
                throw new InvalidOperationException("Data is too large to be decrypted into an array.");
            }

            using var ms = new MemoryStream();
            Decrypt(filename, klicensee, rap, ms);
            return ms.ToArray();
        }

        public static void DecryptSdata(string sdataPath, string outPath)
        {
            using var fs = File.OpenWrite(outPath);
            DecryptSdata(sdataPath, fs);
        }

        public static void DecryptSdata(string sdataPath, Stream output)
        {
            EDATA sdata = Read(sdataPath);
            if (!sdata.IsSdata())
            {
                throw new InvalidDataException($"File is not SDATA: \"{sdataPath}\"");
            }

            sdata.Decrypt(string.Empty, [], [], output);
        }

        #endregion

        #region Encrypt

        /// <summary>
        /// Encrypts either a key or a hash.
        /// </summary>
        /// <param name="keyHash">The key or hash to encrypt.</param>
        private void EncryptKeyHash(Span<byte> keyHash)
        {
            if (IsKeyEncrypted())
            {
                var encryptionKey = KeyVault.EDAT_KEY_0;
                if (NPD.Version == 4)
                {
                    encryptionKey = KeyVault.EDAT_KEY_1;
                }

                AesCrypto.DecryptCbc(keyHash, encryptionKey, KeyVault.EDAT_IV);
            }
        }

        /// <summary>
        /// Encrypts the specified data with the specified parameters.
        /// </summary>
        /// <param name="key">The key to encrypt with.</param>
        /// <param name="iv">The IV to encrypt with.</param>
        /// <param name="hashKey">The key to encrypt the hash with.</param>
        /// <param name="hashResult">The buffer to store the encrypted data hash result in.</param>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="isPlaintext">Whether or not the data is plaintext.</param>
        /// <param name="isUnk4">Whether or not the <see cref="EdataFlags.UNK_4"/> flag was set.</param>
        /// <returns>Whether or not the correct number of bytes were encrypted.</returns>
        private bool EncryptData(Span<byte> key, Span<byte> iv, Span<byte> hashKey, Span<byte> hashResult, Span<byte> data, bool isPlaintext, bool isUnk4)
        {
            // Encrypt the key and hash
            EncryptKeyHash(key);
            EncryptKeyHash(hashKey);

            // Encrypt the block data
            bool result;
            if (!isPlaintext)
            {
                result = AesCrypto.EncryptCbc(data, key, iv) == data.Length;
            }
            else
            {
                result = true;
            }

            // Generate hash for the encrypted data
            if (!isUnk4) // AES-CMAC-128
            {
                AesHash.ComputeAesCmac(hashKey, data, hashResult);
            }
            else // SHA1-HMAC 128 or 160
            {
                ShaHash.ComputeSha1Hmac(hashKey, data, hashResult);
            }

            return result;
        }

        public void Encrypt(ReadOnlySpan<char> filename, ReadOnlySpan<byte> klicensee, ReadOnlySpan<byte> rap, Stream input)
        {
            var output = Data;
            if (output.Position != 0)
            {
                if (!output.CanSeek)
                {
                    throw new Exception("Cannot seek data output back to start for encrypting.");
                }

                output.Seek(0, SeekOrigin.Begin);
            }

            // Ensure flags and version are usable without secretly modifying user state.
            // Notify the user to fix their errors before continuing.
            CheckFlags();

            // Get the length of the soon to be new data
            long dataSize = input.Length;

            // Get encryption key
            Span<byte> key = stackalloc byte[KeySize];
            GetCryptoKey(filename, klicensee, rap, key);

            // Check flags
            bool isDebug = IsDebug();
            bool isCompressed = IsCompressed();
            bool isPlaintext = IsPlaintext();
            bool isUnk2 = (Flags & EdataFlags.UNK_2) != 0;
            bool isKeyEncrypted = IsKeyEncrypted();
            bool isUnk4 = (Flags & EdataFlags.UNK_4) != 0;
            bool isUnk5 = (Flags & EdataFlags.UNK_5) != 0;

            // Calculate sizes
            int numBlocks = (int)((dataSize + BlockSize - 1) / BlockSize);

            // Calculate IV
            bool isOldNpd = NPD.Version <= 1;
            Span<byte> iv = stackalloc byte[16];
            if (!isOldNpd) // NPD versions 1 and below have an empty IV
                NPD.Digest.CopyTo(iv);

            // Setup buffer for metadata hash to be made easier later
            int metadataSectionSize = (isCompressed || isUnk5) ? 32 : 16;
            byte[] metadataBytes = new byte[metadataSectionSize * numBlocks];
            Span<byte> metadataBytesSpan = metadataBytes.AsSpan();
            var mhbw = new BinarySpanWriter(metadataBytesSpan, true);

            // Encrypt data and generate metadata
            int length = 0;
            long offset = 0;
            Span<byte> blockBuffer = stackalloc byte[BlockSize];
            Span<byte> blockKey = stackalloc byte[16];
            Span<byte> encBlockKey = stackalloc byte[16];
            Span<byte> hashKey = stackalloc byte[16];
            Span<byte> hashResult = stackalloc byte[20];
            Span<byte> metadata = stackalloc byte[32];
            Span<byte> encryptedMetadata = stackalloc byte[32];
            var mbw = new BinarySpanWriter(metadata, true);
            for (int blockIndex = 0; blockIndex < numBlocks; blockIndex++)
            {
                // Get the offset and length of the current block
                offset = blockIndex * BlockSize;
                length = BlockSize;

                // If we are on the last block and it is not perfectly fit to a blocksize, use it's remaining length as the length.
                bool isLastBlock = blockIndex == numBlocks - 1;
                int blocksRemainder = (int)(dataSize % BlockSize);
                if (isLastBlock && blocksRemainder > 0)
                    length = blocksRemainder;

                int blockLength = length; // Store the actual length this block will be
                length = (blockLength + 15) & -16; // We need to pad to the nearest 16 byte fixed AES block.

                // Read the original block data
                Span<byte> data = blockBuffer[..length]; // We need the buffer padded to 16 for AES
                input.ReadExactly(data[..blockLength]); // But we only need to read what is required from the stream

                // Generate a block key
                GetBlockKey(blockIndex, blockKey);

                // Encrypt the block key
                AesCrypto.EncryptEcb(blockKey, key, encBlockKey);

                // Get the hash or hash key
                if (isUnk4)
                    AesCrypto.EncryptEcb(encBlockKey, key, hashKey); // Encrypt again if flag 4 is set
                else
                    encBlockKey.CopyTo(hashKey); // Use the encrypted block key as the hash

                // Encrypt in-place if necessary
                if (!isDebug)
                {
                    if (!EncryptData(encBlockKey, iv, hashKey, hashResult, data, isPlaintext, isUnk4))
                    {
                        throw new Exception($"Decryption of block {blockIndex} failed.");
                    }
                }

                // Build the metadata sections and write the blocks with them
                const int metadataStartOffset = 256;
                if (isCompressed)
                {
                    // Prepare offsets
                    const int metadataSize = 32;
                    const int metadataHashSize = 16;
                    long dataOffset = ((long)blockIndex * BlockSize) + ((long)numBlocks * metadataSize);
                    long metadataOffset = (long)blockIndex * metadataSize;

                    // Write to the metadata buffer
                    mbw.Position = 0;
                    mbw.WriteByteSpan(hashResult[..metadataHashSize]);
                    mbw.WriteInt64(dataOffset + metadataStartOffset);
                    mbw.WriteInt32(blockLength);
                    mbw.WriteInt32(0); // compression end

                    // Encrypt metadata
                    if (isOldNpd)
                    {
                        // Metadata section is not encrypted for version 1
                        metadata.CopyTo(encryptedMetadata);
                    }
                    else
                    {
                        metadata[..metadataHashSize].CopyTo(encryptedMetadata);
                        DecryptMetadataSection(metadata, encryptedMetadata[metadataHashSize..]);
                    }

                    // Write metadata
                    output.Seek(metadataOffset, SeekOrigin.Begin);
                    if (IsDebug())
                    {
                        // Write an empty metadata section if debug
                        for (int i = 0; i < metadataSize; i++)
                            encryptedMetadata[i] = 0;

                        output.Write(encryptedMetadata);
                    }
                    else
                    {
                        output.Write(encryptedMetadata);
                    }

                    // Copy metadata to metadata buffer for metadata hash later
                    encryptedMetadata.CopyTo(metadataBytesSpan[mhbw.Position..]);
                    mhbw.Position += metadataSize;

                    // Write data
                    output.Seek(dataOffset, SeekOrigin.Begin);
                    output.Write(data[..length]);
                }
                else if (isUnk5)
                {
                    // Prepare offsets
                    const int metadataSize = 32;
                    long dataOffset = ((long)blockIndex * BlockSize) + (((long)blockIndex + 1) * metadataSize);
                    long metadataOffset = ((long)blockIndex * metadataSize) + offset;

                    // Prepare buffers
                    Span<byte> hashResult1 = metadata[..16];
                    Span<byte> hashResult2 = metadata[16..];

                    // XOR metadata
                    StaticRandom.Random.NextBytes(hashResult2); // Use a fake XOR value
                    hashResult[16..].CopyTo(hashResult2); // Copy the last 4 bytes of the 20 byte hash result

                    for (int i = 0; i < 16; i++)
                        hashResult1[i] = (byte)(hashResult[i] ^ hashResult2[i]); // Apply XOR

                    // Metadata buffer is already filled with hashResult1 and hashResult2
                    // Write metadata
                    output.Seek(metadataOffset, SeekOrigin.Begin);
                    if (IsDebug())
                    {
                        // Write an empty metadata section if debug
                        for (int i = 0; i < metadataSize; i++)
                            metadata[i] = 0;

                        output.Write(metadata);
                    }
                    else
                    {
                        output.Write(metadata);
                    }

                    // Copy metadata to metadata buffer for metadata hash later
                    metadata.CopyTo(metadataBytesSpan[mhbw.Position..]);
                    mhbw.Position += metadataSize;

                    // Write data
                    output.Seek(dataOffset, SeekOrigin.Begin);
                    output.Write(data[..length]);
                }
                else
                {
                    // Prepare offsets
                    const int metadataSize = 16;
                    long dataOffset = ((long)blockIndex * BlockSize) + ((long)numBlocks * metadataSize);
                    long metadataOffset = (long)blockIndex * metadataSize;

                    // Write metadata
                    output.Seek(metadataOffset, SeekOrigin.Begin);
                    if (IsDebug())
                    {
                        // Write an empty metadata section if debug
                        for (int i = 0; i < metadataSize; i++)
                            hashResult[i] = 0;

                        output.Write(hashResult[..metadataSize]);
                    }
                    else
                    {
                        output.Write(hashResult[..metadataSize]);
                    }

                    // Copy metadata to metadata buffer for metadata hash later
                    hashResult[..metadataSize].CopyTo(metadataBytesSpan[mhbw.Position..]);
                    mhbw.Position += metadataSize;

                    // Write data
                    output.Seek(dataOffset, SeekOrigin.Begin);
                    output.Write(data[..length]);
                }
            }

            // Update these last
            // These hashes aren't exposed to the user anyhow, so updating here should be fine.
            // However, validation is, so we expose a way to update them.
            // Update NPD hashes
            NPD.Update(filename, klicensee);

            // Set the length of the new data before updating hashes
            DataSize = dataSize;

            // Update EDATA hashes
            UpdateHashes(key, metadataBytesSpan);
        }

        private void UpdateHashes(Span<byte> key, Span<byte> metadata)
        {
            // Prepare buffers
            Span<byte> extendedHeader = stackalloc byte[160];
            Span<byte> empty = stackalloc byte[16];
            Span<byte> hashKey = stackalloc byte[16];
            Span<byte> metadataHash = MetadataHash;
            Span<byte> extendedHeaderHash = ExtendedHeaderHash;
            key.CopyTo(hashKey);

            // Update metadata hash first
            EncryptData(empty, empty, hashKey, metadataHash, metadata, true, false);
            key.CopyTo(hashKey);

            // Then update the extended header hash
            WriteHeaderBytes(extendedHeader);
            EncryptData(empty, empty, hashKey, extendedHeaderHash, extendedHeader, true, false);

            // Update the ECDSA hashes with random data for now
            StaticRandom.Random.NextBytes(EcdsaMetadataSignature);
            StaticRandom.Random.NextBytes(EcdsaHeaderSignature);
        }

        /// <summary>
        /// Write the <see cref="NPD"/> header bytes.
        /// </summary>
        /// <param name="output">The buffer to output the header bytes into.</param>
        private void WriteHeaderBytes(Span<byte> output)
        {
            var bw = new BinarySpanWriter(output, true);
            bool isDebug = IsDebug();

            NPD.Write(ref bw, isDebug);
            bw.WriteInt32((int)Flags);
            bw.WriteInt32(_BlockSize);
            bw.WriteInt64(DataSize);
            if (isDebug)
                bw.WritePattern(16, 0);
            else
                bw.WriteBytes(MetadataHash);
        }

        #endregion

        #region Data Helpers

        /// <summary>
        /// Set the underlying data stream to a new stream for encrypting.
        /// </summary>
        /// <param name="data">The new stream.</param>
        /// <param name="leaveOldOpen">Whether or not to leave the old stream open.</param>
        public void SetData(Stream data, bool leaveOldOpen = false)
        {
            if (data.Position != 0)
            {
                throw new Exception("Data stream should start at position 0.");
            }

            if (!leaveOldOpen)
            {
                Data.Dispose();
            }

            Data = data;
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
        public bool IsKeyEncrypted()
            => (Flags & EdataFlags.EncryptedKey) != 0;

        private void CheckFlags()
        {
            void NotSupported(EdataFlags unsupportedFlag)
            {
                bool hasFlag = (Flags & unsupportedFlag) != 0;
                if (hasFlag)
                    throw new InvalidDataException($"{nameof(EdataFlags)} \"{unsupportedFlag}\" is not supported in version: \"{NPD.Version}\"");
            }

            void Required(EdataFlags requiredFlag)
            {
                bool hasFlag = (Flags & requiredFlag) != 0;
                if (!hasFlag)
                    throw new InvalidDataException($"{nameof(EdataFlags)} \"{requiredFlag}\" is required in version: \"{NPD.Version}\"");
            }

            void Exclusive(EdataFlags flag, EdataFlags incompatibleFlag)
            {
                bool hasFlag = (Flags & flag) != 0;
                bool hasIncompatibleFlag = (Flags & incompatibleFlag) != 0;
                bool exclusiveError = hasFlag && hasIncompatibleFlag;
                if (exclusiveError)
                    throw new InvalidDataException($"{nameof(EdataFlags)} \"{flag}\" is not compatible with \"{incompatibleFlag}\" in version: \"{NPD.Version}\"");
            }

            // TODO: Flags - These still need more verification through testing
            EdataFlags possibleFlags;
            switch (NPD.Version)
            {
                case 0: // Unclear if this is really even supported
                case 1:
                    NotSupported(EdataFlags.Sdata);
                    NotSupported(EdataFlags.Plaintext);
                    NotSupported(EdataFlags.UNK_2);
                    NotSupported(EdataFlags.EncryptedKey);
                    NotSupported(EdataFlags.UNK_4);
                    NotSupported(EdataFlags.UNK_5);
                    possibleFlags = PossibleFlags1;
                    break;
                case 2:
                    Required(EdataFlags.UNK_2);
                    Required(EdataFlags.EncryptedKey);
                    NotSupported(EdataFlags.UNK_4);
                    NotSupported(EdataFlags.UNK_5);
                    possibleFlags = PossibleFlags2;
                    break;
                case 3:
                case 4:
                    Required(EdataFlags.UNK_2);
                    Required(EdataFlags.EncryptedKey);
                    Exclusive(EdataFlags.Compressed, EdataFlags.UNK_4);
                    Exclusive(EdataFlags.Compressed, EdataFlags.UNK_5);
                    possibleFlags = PossibleFlags3;
                    break;
                default:
                    throw new NotSupportedException($"Unknown EDATA version: \"{NPD.Version}\".");
            }

            var impossibleFlags = ~possibleFlags;
            bool hasImpossibleFlags = (Flags & impossibleFlags) != EdataFlags.None;
            if (hasImpossibleFlags)
            {
                throw new InvalidDataException($"Invalid or unknown {nameof(EdataFlags)} found for version: \"{NPD.Version}\".");
            }
        }

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
                    Data.Dispose();
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
