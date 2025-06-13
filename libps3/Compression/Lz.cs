// Modified for C#
//
// Original copyright notice of lz.cpp:
// Copyright (C) 2014       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 2.0 or later versions.
// http://www.gnu.org/licenses/gpl-2.0.txt

using System;
using System.IO;
using System.Runtime.CompilerServices;

namespace libps3.Compression
{
    public static class Lz
    {
        unsafe static void DecodeRange(uint* range, uint* code, byte** src)
        {
            if (((*range) >> 24) == 0)
            {
                (*range) <<= 8;
                *code = ((*code) << 8) + (*src)++[5];
            }
        }

        unsafe static int DecodeBit(uint* range, uint* code, int* index, byte** src, byte* c)
        {
            DecodeRange(range, code, src);

            uint val = ((*range) >> 8) * (*c);

            *c -= (byte)((*c) >> 3);
            if (index != null) (*index) <<= 1;

            if (*code < val)
            {
                *range = val;
                *c += 31;
                if (index != null) (*index)++;
                return 1;
            }
            else
            {
                *code -= val;
                *range -= val;
                return 0;
            }
        }

        unsafe static int DecodeNumber(byte* ptr, int index, int* bit_flag, uint* range, uint* code, byte** src)
        {
            int i = 1;

            if (index >= 3)
            {
                DecodeBit(range, code, &i, src, ptr + 0x18);
                if (index >= 4)
                {
                    DecodeBit(range, code, &i, src, ptr + 0x18);
                    if (index >= 5)
                    {
                        DecodeRange(range, code, src);
                        for (; index >= 5; index--)
                        {
                            i <<= 1;
                            (*range) >>= 1;
                            if (*code < *range)
                                i++;
                            else
                                (*code) -= *range;
                        }
                    }
                }
            }

            *bit_flag = DecodeBit(range, code, &i, src, ptr);

            if (index >= 1)
            {
                DecodeBit(range, code, &i, src, ptr + 0x8);
                if (index >= 2)
                {
                    DecodeBit(range, code, &i, src, ptr + 0x10);
                }
            }

            return i;
        }

        unsafe static int DecodeWord(byte* ptr, int index, int* bit_flag, uint* range, uint* code, byte** src)
        {
            int i = 1;
            index /= 8;

            if (index >= 3)
            {
                DecodeBit(range, code, &i, src, ptr + 4);
                if (index >= 4)
                {
                    DecodeBit(range, code, &i, src, ptr + 4);
                    if (index >= 5)
                    {
                        DecodeRange(range, code, src);
                        for (; index >= 5; index--)
                        {
                            i <<= 1;
                            (*range) >>= 1;
                            if (*code < *range)
                                i++;
                            else
                                (*code) -= *range;
                        }
                    }
                }
            }

            *bit_flag = DecodeBit(range, code, &i, src, ptr);

            if (index >= 1)
            {
                DecodeBit(range, code, &i, src, ptr + 1);
                if (index >= 2)
                {
                    DecodeBit(range, code, &i, src, ptr + 2);
                }
            }

            return i;
        }

        // No idea if this works or not
        unsafe static int Decompress(byte* output, byte* input, uint size)
        {
            int result;

            fixed (byte* tmp = new byte[0xCC8])
            {
                int offset = 0;
                int bit_flag = 0;
                int data_length = 0;
                int data_offset = 0;

                byte* tmp_sect1;
                byte* tmp_sect2;
                byte* tmp_sect3;
                byte* buf_start;
                byte* buf_end;
                byte prev = 0;

                byte* start = output;
                byte* end = (output + size);
                byte head = input[0];

                uint range = 0xFFFFFFFF;
                uint code = (uint)((input[1] << 24) | (input[2] << 16) | (input[3] << 8) | input[4]);

                if (head > 0x80) // Check if we have a valid starting byte.
                {
                    // The dictionary header is invalid, the data is not compressed.
                    result = -1;
                    if (code <= size)
                    {
                        Buffer.MemoryCopy(input + 5, output, size, code);
                        result = (int)(start - output);
                    }
                }
                else
                {
                    // Set up a temporary buffer (sliding window).
                    Unsafe.InitBlockUnaligned(tmp, 0x80, 0xCA8);
                    while (true)
                    {
                        // Start reading at 0xB68.
                        tmp_sect1 = tmp + offset + 0xB68;
                        if (DecodeBit(&range, &code, null, &input, tmp_sect1) == 0)  // Raw char.
                        {
                            // Adjust offset and check for stream end.
                            if (offset > 0) offset--;
                            if (start == end) return (int)(start - output);

                            // Locate first section.
                            int sect = (((((((int)(start - output)) & 7) << 8) + prev) >> head) & 7) * 0xFF - 1;
                            tmp_sect1 = tmp + sect;
                            int index = 1;

                            // Read, decode and write back.
                            do
                            {
                                DecodeBit(&range, &code, &index, &input, tmp_sect1 + index);
                            } while ((index >> 8) == 0);

                            // Save index.
                            *(int*)start++ = index;
                        }
                        else  // Compressed char stream.
                        {
                            int index = -1;

                            // Identify the data length bit field.
                            do
                            {
                                tmp_sect1 += 8;
                                bit_flag = DecodeBit(&range, &code, null, &input, tmp_sect1);
                                index += bit_flag;
                            } while ((bit_flag != 0) && (index < 6));

                            // Default block size is 0x160.
                            int b_size = 0x160;
                            tmp_sect2 = tmp + index + 0x7F1;

                            // If the data length was found, parse it as a number.
                            if ((index >= 0) || (bit_flag != 0))
                            {
                                // Locate next section.
                                int sect = (index << 5) | (((((int)(start - output)) << index) & 3) << 3) | (offset & 7);
                                tmp_sect1 = tmp + 0xBA8 + sect;

                                // Decode the data length (8 bit fields).
                                data_length = DecodeNumber(tmp_sect1, index, &bit_flag, &range, &code, &input);
                                if (data_length == 0xFF) return (int)(start - output);  // End of stream.
                            }
                            else
                            {
                                // Assume one byte of advance.
                                data_length = 1;
                            }

                            // If we got valid parameters, seek to find data offset.
                            if ((data_length <= 2))
                            {
                                tmp_sect2 += 0xF8;
                                b_size = 0x40;  // Block size is now 0x40.
                            }

                            int diff = 0;
                            int shift = 1;

                            // Identify the data offset bit field.
                            do
                            {
                                diff = (shift << 4) - b_size;
                                bit_flag = DecodeBit(&range, &code, &shift, &input, tmp_sect2 + (shift << 3));
                            } while (diff < 0);

                            // If the data offset was found, parse it as a number.
                            if ((diff > 0) || (bit_flag != 0))
                            {
                                // Adjust diff if needed.
                                if (bit_flag == 0) diff -= 8;

                                // Locate section.
                                tmp_sect3 = tmp + 0x928 + diff;

                                // Decode the data offset (1 bit fields).
                                data_offset = DecodeWord(tmp_sect3, diff, &bit_flag, &range, &code, &input);
                            }
                            else
                            {
                                // Assume one byte of advance.
                                data_offset = 1;
                            }

                            // Set buffer start/end.
                            buf_start = start - data_offset;
                            buf_end = start + data_length + 1;

                            // Underflow.
                            if (buf_start < output)
                            {
                                return -1;
                            }

                            // Overflow.
                            if (buf_end > end)
                            {
                                return -1;
                            }

                            // Update offset.
                            offset = ((((int)(buf_end - output)) + 1) & 1) + 6;

                            // Copy data.
                            do
                            {
                                *start++ = *buf_start++;
                            } while (start < buf_end);

                        }
                        prev = *(start - 1);
                    }
                    result = (int)(start - output);
                }

                return result;
            }
        }

        public unsafe static int Decompress(ref Span<byte> output, Span<byte> input, uint size)
        {
            fixed (byte* o = output)
            fixed (byte* i = input)
            {
                return Decompress(o, i, size);
            }
        }

        public static int Decompress(Stream output, Span<byte> input, uint size)
        {
            Span<byte> o = stackalloc byte[(int)size];
            int result = Decompress(ref o, input, size);
            output.Write(o);
            return result;
        }
    }
}
