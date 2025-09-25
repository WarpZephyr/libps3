// Adapted from RPCS3 C++ to C#
// Refer to RPCS3 for licensing regarding this code

using Edoke.IO;
using libps3.Compression;
using libps3.Cryptography;
using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;

namespace libps3
{
    public static class EDAT
    {
        private const uint SDAT_FLAG = 0x01000000;
        private const uint EDAT_COMPRESSED_FLAG = 0x00000001;
        private const uint EDAT_FLAG_ENCRYPTED = 0x00000002;
        private const uint EDAT_ENCRYPTED_KEY_FLAG = 0x00000008;
        private const uint EDAT_FLAG_0x10 = 0x00000010;
        private const uint EDAT_FLAG_0x20 = 0x00000020;
        private const uint EDAT_DEBUG_DATA_FLAG = 0x80000000;

        private const int ENCRYPTED_KEYHASH_MODE = 0b00010000_00000000_00000000_00000000;
        private const int DEFAULT_KEYHASH_MODE   = 0b00100000_00000000_00000000_00000000;
        private const int ORIGINAL_KEYHASH_MODE  = 0b00000000_00000000_00000000_00000000;
        private const int DEBUG_MODE             = 0b00000001_00000000_00000000_00000000;
        private const int HASHMODE_SHA1HMAC = 1;
        private const int HASHMODE_AESCMAC = 2;
        private const int HASHMODE_SHA1HMAC_SHORT = 4;
        private const int CRYPTOMODE_UNENCRYPTED = 1;
        private const int CRYPTOMODE_AESCBC128 = 2;

        public static void DecryptSdat(string path, string outPath)
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.Read);
            DecryptSdat(input, output);
        }

        public static void DecryptSdat(Stream input, Stream output)
            => Decrypt(input, output, [], [], string.Empty);

        public static void Decrypt(string path, string outPath, byte[] klicensee, byte[] rap, string filename)
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.Read);
            Decrypt(input, output, klicensee, rap, filename);
        }

        public static void Decrypt(Stream input, Stream output, byte[] klicensee, byte[] rap, string filename)
        {
            using BinaryStreamReader br = new BinaryStreamReader(input, true);
            NpdHeader npd = new NpdHeader(br);
            EdatHeader edat = new EdatHeader(br);

            byte[] key = new byte[16];
            if ((edat.flags & SDAT_FLAG) == SDAT_FLAG)
            {
                ByteOperation.Xor(npd.headerHash, KeyVault.SDAT_KEY, key);
            }
            else
            {
                // Perform header validation (EDAT only).
                if (!npd.HashesValid(klicensee, filename))
                {
                    throw new InvalidDataException("NPD hash validation failed!");
                }

                // Type 3: Use supplied klicensee.
                if ((npd.license & 0x3) == 0x3)
                {
                    key = klicensee;
                }
                else // Type 2: Use key from RAP file (RIF key). (also used for type 1 at the moment)
                {
                    key = RAP.RapToRif(rap);
                }
            }

            // TODO CheckData

            input.Position = 0;
            int totalBlocks = (int)((edat.dataSize + (ulong)edat.blockSize - 1) / (ulong)edat.blockSize);
            ulong sizeLeft = edat.dataSize;

            for (int i = 0; i < totalBlocks; i++)
            {
                input.Position = 0;
                using MemoryStream o = new MemoryStream(new byte[sizeLeft < (ulong)edat.blockSize ? (int)sizeLeft : edat.blockSize], true);
                long result = DecryptBlock(input, o, npd, edat, key, (uint)i, (uint)totalBlocks, sizeLeft);

                // TODO check result

                sizeLeft -= (ulong)result;
                o.Position = 0;
                o.CopyTo(output, (int)result);
            }
        }

        private static long DecryptBlock(Stream input, Stream output, NpdHeader npd, EdatHeader edat, byte[] key, uint blockNum, uint totalBlocks, ulong sizeLeft)
        {
            // Get metadata info and setup buffers.
            int metadataSectionSize = ((edat.flags & EDAT_COMPRESSED_FLAG) != 0 || (edat.flags & EDAT_FLAG_0x20) != 0) ? 0x20 : 0x10;
            int metadataOffset = 0x100;

            byte[] hash = new byte[0x14];

            long offset = 0;
            long metadataSectionOffset = 0;
            int length = 0;
            int compressionEnd = 0;

            long fileOffset = input.Position;

            // Decrypt the metadata.
            if ((edat.flags & EDAT_COMPRESSED_FLAG) != 0)
            {
                metadataSectionOffset = metadataOffset + (blockNum * metadataSectionSize);
                input.Position = fileOffset + metadataSectionOffset;
                byte[] metadata = new byte[0x20];
                if (input.Read(metadata) != metadata.Length)
                {
                    throw new Exception("Failed to read required number of bytes for metadata section of block.");
                }

                (offset, length, compressionEnd) = ReadMetadataSection(npd.version, metadata);

                Array.Copy(metadata, hash, 0x10);
            }
            else if ((edat.flags & EDAT_FLAG_0x20) != 0)
            {
                // If FLAG 0x20, the metadata precedes each data block.
                metadataSectionOffset = metadataOffset + (blockNum * (metadataSectionSize + edat.blockSize));
                input.Position = fileOffset + metadataSectionOffset;
                byte[] metadata = new byte[0x20];
                if (input.Read(metadata, 0, metadata.Length) != metadata.Length)
                {
                    throw new Exception("Failed to read required number of bytes for metadata section of block.");
                }

                Array.Copy(metadata, hash, 0x14);

                // If FLAG 0x20 is set, apply custom xor.
                for (int j = 0; j < 0x10; j++)
                    hash[j] = (byte)(metadata[j] ^ metadata[j + 0x10]);

                offset = metadataSectionOffset + 0x20;
                length = edat.blockSize;

                if (blockNum == (totalBlocks - 1))
                {
                    ulong mod = edat.dataSize % (ulong)edat.blockSize;
                    if (mod != 0)
                    {
                        length = (int)mod;
                    }
                }
            }
            else
            {
                metadataSectionOffset = metadataOffset + (blockNum * metadataSectionSize);
                input.Position = fileOffset + metadataSectionOffset;

                byte[] result = new byte[0x10];
                if (input.Read(result, 0, result.Length) != result.Length)
                {
                    throw new Exception("Failed to read required number of bytes for metadata section of block.");
                }

                Array.Copy(result, hash, 0x10);
                offset = metadataOffset + ((blockNum * edat.blockSize) + (totalBlocks * metadataSectionSize));
                length = edat.blockSize;

                if (blockNum == (totalBlocks - 1))
                {
                    ulong mod = edat.dataSize % (ulong)edat.blockSize;
                    if (mod != 0)
                    {
                        length = (int)mod;
                    }
                }
            }

            // Locate the real data.
            uint padLength = (uint)length;
            length = (int)((padLength + 0xF) & 0xFFFFFFF0);

            byte[] encData = new byte[length];
            byte[] decData = new byte[length];

            input.Position = fileOffset + offset;
            if (input.Read(encData) != encData.Length)
            {
                throw new Exception("Failed to read the required number of bytes for encrypted data of block.");
            }

            byte[] blockKey = GetBlockKey(blockNum, npd);
            byte[] keyResult = CryptoHelper.EncryptAesEcb(key, blockKey);
            byte[] hashKey;
            if ((edat.flags & EDAT_FLAG_0x10) != 0)
                hashKey = CryptoHelper.EncryptAesEcb(key, keyResult);  // If FLAG 0x10 is set, encrypt again to get the final hash.
            else
            {
                hashKey = new byte[0x10];
                Array.Copy(keyResult, hashKey, 0x10);
            }

            // Setup the crypto and hashing mode based on the extra flags.
            int crypto_mode = ((edat.flags & EDAT_FLAG_ENCRYPTED) == 0) ? CRYPTOMODE_AESCBC128 : CRYPTOMODE_UNENCRYPTED;
            int hash_mode;

            if ((edat.flags & EDAT_FLAG_0x10) == 0)
                hash_mode = HASHMODE_AESCMAC;
            else if ((edat.flags & EDAT_FLAG_0x20) == 0)
                hash_mode = HASHMODE_SHA1HMAC_SHORT;
            else
                hash_mode = HASHMODE_SHA1HMAC;

            if ((edat.flags & EDAT_ENCRYPTED_KEY_FLAG) != 0)
            {
                crypto_mode |= ENCRYPTED_KEYHASH_MODE;
                hash_mode |= ENCRYPTED_KEYHASH_MODE;
            }

            if ((edat.flags & EDAT_DEBUG_DATA_FLAG) != 0)
            {
                // Reset the flags.
                crypto_mode |= DEBUG_MODE;
                hash_mode |= DEBUG_MODE;

                // Simply copy the data without the header or the footer.
                decData = encData;
            }
            else
            {
                // IV is null if NPD version is 1 or 0.
                byte[] iv = (npd.version <= 1) ? new byte[0x10] : npd.digest;

                // Call main crypto routine on this data block.
                if (!DecryptData(hash_mode, crypto_mode, (npd.version == 4), encData, ref decData, length, keyResult, iv, hashKey, hash))
                {
                    throw new InvalidDataException($"Block at offset {offset} has invalid hash!");
                }
            }

            // Apply additional de-compression if needed and write the decrypted data.
            if (((edat.flags & EDAT_COMPRESSED_FLAG) != 0) && (compressionEnd != 0))
            {
                int res = Lz.Decompress(output, decData, (uint)edat.blockSize);

                sizeLeft -= (ulong)res;

                if (sizeLeft == 0)
                {
                    if (res < 0)
                    {
                        throw new Exception("Decompression failed!");
                    }
                }

                return res;
            }
            else
            {
                output.Write(decData.ToArray(), 0, (int)padLength);
                return padLength;
            }
        }

        private unsafe static byte[] GetBlockKey(uint block, NpdHeader npd)
        {
            byte[] destKey = (npd.version <= 1) ? new byte[0x10] : npd.headerHash;

            if (BitConverter.IsLittleEndian)
            {
                block = BinaryPrimitives.ReverseEndianness(block);
            }

            fixed (byte* bp = destKey)
            {
                Unsafe.WriteUnaligned(bp + 0xC, block);
            }

            return destKey;
        }

        private static (long, int, int) ReadMetadataSection(uint version, byte[] metadata)
        {
            long offset;
            int length;
            int compressionEnd;

            if (version <= 1)
            {
                offset = BinaryPrimitives.ReadInt64BigEndian(metadata);
                length = BinaryPrimitives.ReadInt32BigEndian(metadata[8..]);
                compressionEnd = BinaryPrimitives.ReadInt32BigEndian(metadata[12..]);
            }
            else
            {
                Span<byte> dec =
                [
                    (byte)(metadata[0xC] ^ metadata[0x8] ^ metadata[0x10]),
                    (byte)(metadata[0xD] ^ metadata[0x9] ^ metadata[0x11]),
                    (byte)(metadata[0xE] ^ metadata[0xA] ^ metadata[0x12]),
                    (byte)(metadata[0xF] ^ metadata[0xB] ^ metadata[0x13]),
                    (byte)(metadata[0x4] ^ metadata[0x8] ^ metadata[0x14]),
                    (byte)(metadata[0x5] ^ metadata[0x9] ^ metadata[0x15]),
                    (byte)(metadata[0x6] ^ metadata[0xA] ^ metadata[0x16]),
                    (byte)(metadata[0x7] ^ metadata[0xB] ^ metadata[0x17]),
                    (byte)(metadata[0xC] ^ metadata[0x0] ^ metadata[0x18]),
                    (byte)(metadata[0xD] ^ metadata[0x1] ^ metadata[0x19]),
                    (byte)(metadata[0xE] ^ metadata[0x2] ^ metadata[0x1A]),
                    (byte)(metadata[0xF] ^ metadata[0x3] ^ metadata[0x1B]),
                    (byte)(metadata[0x4] ^ metadata[0x0] ^ metadata[0x1C]),
                    (byte)(metadata[0x5] ^ metadata[0x1] ^ metadata[0x1D]),
                    (byte)(metadata[0x6] ^ metadata[0x2] ^ metadata[0x1E]),
                    (byte)(metadata[0x7] ^ metadata[0x3] ^ metadata[0x1F]),
                ];

                offset = BinaryPrimitives.ReadInt64BigEndian(dec);
                length = BinaryPrimitives.ReadInt32BigEndian(dec[8..]);
                compressionEnd = BinaryPrimitives.ReadInt32BigEndian(dec[12..]);
            }

            return (offset, length, compressionEnd);
        }

        private static bool DecryptData(int hash_mode, int crypto_mode, bool version, byte[] input, ref byte[] output, int length, byte[] key, byte[] iv, byte[] hashKey, byte[] hash)
        {
            byte[] key_final = new byte[0x10];
            byte[] iv_final = new byte[0x10];
            byte[] hash_key_final_10 = new byte[0x10];
            byte[] hash_key_final_14 = new byte[0x14];

            // Generate crypto key and hash.
            GenerateKey(crypto_mode, version, ref key_final, ref iv_final, key, iv);
            if ((hash_mode & 0xFF) == HASHMODE_SHA1HMAC)
            {
                GenerateHash(hash_mode, version, ref hash_key_final_14, hashKey);
            }
            else
            {
                GenerateHash(hash_mode, version, ref hash_key_final_10, hashKey);
            }

            if ((crypto_mode & 0xFF) == CRYPTOMODE_UNENCRYPTED)  // No algorithm.
            {
                output = input;
            }
            else if ((crypto_mode & 0xFF) == CRYPTOMODE_AESCBC128)  // AES128-CBC
            {
                output = CryptoHelper.DecryptAesCbc(key_final, iv_final, input);
            }
            else
            {
                throw new InvalidOperationException($"Unknown crypto algorithm: {crypto_mode}");
            }

            if ((hash_mode & 0xFF) == HASHMODE_SHA1HMAC) // 0x14 SHA1-HMAC
            {
                return CryptoHelper.CompareSha1Hmac(hash_key_final_14, input, hash);
            }
            else if ((hash_mode & 0xFF) == HASHMODE_AESCMAC)  // 0x10 AES-CMAC
            {
                return CryptoHelper.CompareAesCmac(hash_key_final_10, input, hash);
            }
            else if ((hash_mode & 0xFF) == HASHMODE_SHA1HMAC_SHORT) //0x10 SHA1-HMAC
            {
                return CryptoHelper.CompareSha1Hmac(hash_key_final_10, input, hash);
            }
            else
            {
                throw new InvalidOperationException($"Unknown hashing algorithm: {hash_mode}");
            }
        }

        private static void GenerateKey(int crypto_mode, bool version, ref byte[] key_final, ref byte[] iv_final, byte[] key, byte[] iv)
        {
            int mode = (int)(((uint)crypto_mode) & 0xF0_00_00_00);
            switch (mode)
            {
                case ENCRYPTED_KEYHASH_MODE:
                    // Encrypted ERK.
                    // Decrypt the key with EDAT_KEY + EDAT_IV and copy the original IV.
                    key_final = CryptoHelper.DecryptAesCbc(version ? KeyVault.EDAT_KEY_1 : KeyVault.EDAT_KEY_0, KeyVault.EDAT_IV, key);
                    iv_final = iv;
                    break;
                case DEFAULT_KEYHASH_MODE:
                    // Default ERK.
                    // Use EDAT_KEY and EDAT_IV.
                    key_final = version ? KeyVault.EDAT_KEY_1 : KeyVault.EDAT_KEY_0;
                    iv_final = KeyVault.EDAT_IV;
                    break;
                case ORIGINAL_KEYHASH_MODE:
                    // Unencrypted ERK.
                    // Use the original key and iv.
                    key_final = key;
                    iv_final = iv;
                    break;
                default:
                    throw new InvalidOperationException($"Unknown crypto algorithm: {crypto_mode}");
            }
        }

        private static void GenerateHash(int hash_mode, bool version, ref byte[] hash_final, byte[] hash)
        {
            int mode = (int)(((uint)hash_mode) & 0xF0_00_00_00);
            switch (mode)
            {
                case ENCRYPTED_KEYHASH_MODE:
                    // Encrypted HASH.
                    // Decrypt the hash with EDAT_KEY + EDAT_IV.
                    hash_final = CryptoHelper.DecryptAesCbc(version ? KeyVault.EDAT_KEY_1 : KeyVault.EDAT_KEY_0, KeyVault.EDAT_IV, hash);
                    break;
                case DEFAULT_KEYHASH_MODE:
                    // Default HASH.
                    // Use EDAT_HASH.
                    hash_final = version ? KeyVault.EDAT_HASH_1 : KeyVault.EDAT_HASH_0;
                    break;
                case ORIGINAL_KEYHASH_MODE:
                    // Unencrypted ERK.
                    // Use the original hash.
                    hash_final = hash;
                    break;
                default:
                    throw new InvalidOperationException($"Unknown hashing algorithm: {hash_mode}");
            }
        }
    }
}
