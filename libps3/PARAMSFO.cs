using Edoke.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace libps3
{
    public class PARAMSFO
    {
        /// <summary>
        /// The parameters in the PARAM.SFO.
        /// </summary>
        public Dictionary<string, Parameter> Parameters { get; set; }

        /// <summary>
        /// The format version of the PARAM.SFO.
        /// </summary>
        public FormatVersion Version { get; set; }

        public PARAMSFO()
        {
            Parameters = [];
            Version = new FormatVersion();
        }

        public PARAMSFO(int parameterCapacity)
        {
            Parameters = new Dictionary<string, Parameter>(parameterCapacity);
            Version = new FormatVersion();
        }

        public PARAMSFO(int parameterCapacity, FormatVersion version)
        {
            Parameters = new Dictionary<string, Parameter>(parameterCapacity);
            Version = version;
        }

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

        public static PARAMSFO Read(string path)
        {
            using BinaryStreamReader br = new BinaryStreamReader(path, true);
            return Read(br);
        }

        public static PARAMSFO Read(byte[] bytes)
        {
            using BinaryStreamReader br = new BinaryStreamReader(bytes, true);
            return Read(br);
        }

        public static PARAMSFO Read(Stream stream)
        {
            using BinaryStreamReader br = new BinaryStreamReader(stream, true);
            return Read(br);
        }

        public static bool IsRead(string path, [NotNullWhen(true)] out PARAMSFO? obj)
        {
            using BinaryStreamReader br = new BinaryStreamReader(path, true);
            return IsRead(br, out obj);
        }

        public static bool IsRead(byte[] bytes, [NotNullWhen(true)] out PARAMSFO? obj)
        {
            using BinaryStreamReader br = new BinaryStreamReader(bytes, true);
            return IsRead(br, out obj);
        }

        public static bool IsRead(Stream stream, [NotNullWhen(true)] out PARAMSFO? obj)
        {
            using BinaryStreamReader br = new BinaryStreamReader(stream, true);
            return IsRead(br, out obj);
        }

        private static bool IsRead(BinaryStreamReader br, [NotNullWhen(true)] out PARAMSFO? obj)
        {
            if (Is(br))
            {
                obj = Read(br);
                return true;
            }

            obj = null;
            return false;
        }

        public void Write(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new NullReferenceException($"Failed to get directory name for: {path}"));
            using BinaryStreamWriter bw = new BinaryStreamWriter(path, true);
            Write(bw);
        }

        public byte[] Write()
        {
            using BinaryStreamWriter bw = new BinaryStreamWriter(true);
            Write(bw);
            return bw.FinishBytes();
        }

        #endregion

        private static bool Is(BinaryStreamReader br)
        {
            br.BigEndian = true;
            return br.Length >= 20 && br.GetASCII(br.Position, 4) == "\0PSF";
        }

        private static PARAMSFO Read(BinaryStreamReader br)
        {
            br.BigEndian = false;
            br.AssertASCII("\0PSF");
            var version = new FormatVersion(br);
            uint keyTableStart = br.ReadUInt32();
            uint dataTableStart = br.ReadUInt32();
            uint tableEntryCount = br.ReadUInt32();

            PARAMSFO obj = new PARAMSFO((int)tableEntryCount, version);
            for (int i = 0; i < tableEntryCount; i++)
            {
                _ = new Parameter(br, obj.Parameters, keyTableStart, dataTableStart);
            }

            return obj;
        }

        private void Write(BinaryStreamWriter bw)
        {
            bw.BigEndian = true;
            bw.WriteASCII("\0PSF", false);
            Version.Write(bw);
            bw.ReserveUInt32("KeyTableStart");
            bw.ReserveUInt32("DataTableStart");

            uint count = (uint)Parameters.Count;
            bw.WriteUInt32(count);

            List<string> keys = new List<string>(Parameters.Keys);
            List<Parameter> parameters = new List<Parameter>(Parameters.Values);

            for (int i = 0; i < count; i++)
            {
                parameters[i].WriteEntry(bw, i);
            }

            long keyTableStart = bw.Position;
            bw.FillUInt32("KeyTableStart", (uint)keyTableStart);
            for (int i = 0; i < count; i++)
            {
                bw.FillUInt16($"KeyOffset_{i}", (ushort)(bw.Position - keyTableStart));
                bw.WriteUTF8(keys[i], true);
            }
            bw.Pad(4);

            long dataTableStart = bw.Position;
            bw.FillUInt32("DataTableStart", (uint)dataTableStart);
            for (int i = 0; i < count; i++)
            {
                bw.FillUInt32($"DataOffset_{i}", (uint)(bw.Position - dataTableStart));
                Parameter parameter = parameters[i];
                DataFormat format = parameter.Format;
                switch (format)
                {
                    case DataFormat.UTF8S:
                        bw.WriteUTF8(parameter.Data, false);
                        bw.WritePattern((int)(parameter.DataMaxLength - parameter.Data.Length), 0);
                        break;
                    case DataFormat.UTF8:
                        bw.WriteUTF8(parameter.Data, true);
                        bw.WritePattern((int)(parameter.DataMaxLength - (parameter.Data.Length + 1)), 0);
                        break;
                    case DataFormat.UInt32:
                        bw.WriteUInt32(uint.Parse(parameter.Data));
                        break;
                    default:
                        throw new InvalidDataException($"{nameof(DataFormat)} {format} is not supported or implemented.");
                }
            }
        }

        public class Parameter
        {
            public string Data { get; set; }
            public DataFormat Format { get; set; }
            public uint DataMaxLength { get; set; }

            public Parameter(string value)
            {
                Data = value;
                Format = DataFormat.UTF8;
            }

            public Parameter(string value, DataFormat dataFormat)
            {
                Data = value;
                Format = dataFormat;
                DataMaxLength = (uint)value.Length;
            }

            public Parameter(string value, DataFormat dataFormat, uint dataMaxLength)
            {
                Data = value;
                Format = dataFormat;
                DataMaxLength = dataMaxLength;
            }

            internal Parameter(BinaryStreamReader br, Dictionary<string, Parameter> dictionary, uint keyTableStart, uint dataTableStart)
            {
                ushort keyOffset = br.ReadUInt16();
                Format = (DataFormat)br.ReadUInt16();
                uint dataLength = br.ReadUInt32();
                DataMaxLength = br.ReadUInt32();
                uint dataOffset = br.ReadUInt32();

                long end = br.Position;
                br.Position = keyTableStart + keyOffset;
                string key = br.ReadUTF8();

                br.Position = dataTableStart + dataOffset;
                Data = Format switch
                {
                    DataFormat.UTF8S => br.ReadUTF8((int)dataLength),
                    DataFormat.UTF8 => br.ReadUTF8(),
                    DataFormat.UInt32 => br.ReadUInt32().ToString(),
                    _ => throw new InvalidDataException($"{nameof(DataFormat)} {Format} is not supported or implemented."),
                };
                dictionary.Add(key, this);
                br.Position = end;
            }

            internal void WriteEntry(BinaryStreamWriter bw, int index)
            {
                bw.ReserveUInt16($"KeyOffset_{index}");
                bw.WriteUInt16((ushort)Format);

                if (Format == DataFormat.UInt32)
                {
                    bw.WriteUInt32(4);
                    bw.WriteUInt32(4);
                }
                else
                {
                    bw.WriteUInt32((uint)Data.Length);
                    bw.WriteUInt32(DataMaxLength);
                }

                bw.ReserveUInt32($"DataOffset_{index}");
            }
        }

        public class FormatVersion
        {
            public byte Major { get; set; }
            public byte Minor { get; set; }
            public byte Unk03 { get; set; }
            public byte Unk04 { get; set; }

            public FormatVersion()
            {
                Major = 1;
                Minor = 1;
                Unk03 = 0;
                Unk04 = 0;
            }

            public FormatVersion(byte major, byte minor)
            {
                Major = major;
                Minor = minor;
                Unk03 = 0;
                Unk04 = 0;
            }

            public FormatVersion(byte major, byte minor, byte unk03, byte unk04)
            {
                Major = major;
                Minor = minor;
                Unk03 = unk03;
                Unk04 = unk04;
            }

            internal FormatVersion(BinaryStreamReader br)
            {
                Major = br.ReadByte();
                Minor = br.ReadByte();
                Unk03 = br.ReadByte();
                Unk04 = br.ReadByte();
            }

            internal void Write(BinaryStreamWriter bw)
            {
                bw.WriteByte(Major);
                bw.WriteByte(Minor);
                bw.WriteByte(Unk03);
                bw.WriteByte(Unk04);
            }
        }

        public enum DataFormat : ushort
        {
            /// <summary>
            /// UTF8 without null termination.
            /// </summary>
            UTF8S = 0x0004,

            /// <summary>
            /// UTF8.
            /// </summary>
            UTF8 = 0x0204,

            /// <summary>
            /// UInt32.
            /// </summary>
            UInt32 = 0x0404
        }
    }
}
