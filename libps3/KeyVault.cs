﻿namespace libps3
{
    internal static class KeyVault
    {
        internal readonly static byte[] NP_RIF_KEY                      = [0xDA, 0x7D, 0x4B, 0x5E, 0x49, 0x9A, 0x4F, 0x53, 0xB1, 0xC1, 0xA1, 0x4A, 0x74, 0x84, 0x44, 0x3B];
        internal readonly static byte[] NP_PSP_KEY                      = [0x2A, 0x6A, 0xFB, 0xCF, 0x43, 0xD1, 0x57, 0x9F, 0x7D, 0x73, 0x87, 0x41, 0xA1, 0x3B, 0xD4, 0x2E];
        internal readonly static byte[] NP_PE_KEY                       = [0x0D, 0xB8, 0x57, 0x32, 0x36, 0x6C, 0xD7, 0x34, 0xFC, 0x87, 0x9E, 0x74, 0x33, 0x43, 0xBB, 0x4F];
        internal readonly static byte[] NP_PSX_KEY                      = [0x52, 0xC0, 0xB5, 0xCA, 0x76, 0xD6, 0x13, 0x4B, 0xB4, 0x5F, 0xC6, 0x6C, 0xA6, 0x37, 0xF2, 0xC1];
        internal readonly static byte[] NP_KLIC_KEY                     = [0xF2, 0xFB, 0xCA, 0x7A, 0x75, 0xB0, 0x4E, 0xDC, 0x13, 0x90, 0x63, 0x8C, 0xCD, 0xFD, 0xD1, 0xEE];
        internal readonly static byte[] NP_KLIC_FREE                    = [0x72, 0xF9, 0x90, 0x78, 0x8F, 0x9C, 0xFF, 0x74, 0x57, 0x25, 0xF0, 0x8E, 0x4C, 0x12, 0x83, 0x87];
        internal readonly static byte[] NP_HEADER_OMAC_KEY              = [0x6B, 0xA5, 0x29, 0x76, 0xEF, 0xDA, 0x16, 0xEF, 0x3C, 0x33, 0x9F, 0xB2, 0x97, 0x1E, 0x25, 0x6B];
        internal readonly static byte[] NP_TITLE_OMAC_KEY               = [0x9B, 0x51, 0x5F, 0xEA, 0xCF, 0x75, 0x06, 0x49, 0x81, 0xAA, 0x60, 0x4D, 0x91, 0xA5, 0x4E, 0x97];
        internal readonly static byte[] SDAT_KEY                        = [0x0D, 0x65, 0x5E, 0xF8, 0xE6, 0x74, 0xA9, 0x8A, 0xB8, 0x50, 0x5C, 0xFA, 0x7D, 0x01, 0x29, 0x33];
        internal readonly static byte[] EDAT_KEY_0                      = [0xBE, 0x95, 0x9C, 0xA8, 0x30, 0x8D, 0xEF, 0xA2, 0xE5, 0xE1, 0x80, 0xC6, 0x37, 0x12, 0xA9, 0xAE];
        internal readonly static byte[] EDAT_KEY_1                      = [0x4C, 0xA9, 0xC1, 0x4B, 0x01, 0xC9, 0x53, 0x09, 0x96, 0x9B, 0xEC, 0x68, 0xAA, 0x0B, 0xC0, 0x81];
        internal readonly static byte[] EDAT_HASH_0                     = [0xEF, 0xFE, 0x5B, 0xD1, 0x65, 0x2E, 0xEB, 0xC1, 0x19, 0x18, 0xCF, 0x7C, 0x04, 0xD4, 0xF0, 0x11];
        internal readonly static byte[] EDAT_HASH_1                     = [0x3D, 0x92, 0x69, 0x9B, 0x70, 0x5B, 0x07, 0x38, 0x54, 0xD8, 0xFC, 0xC6, 0xC7, 0x67, 0x27, 0x47];
        internal readonly static byte[] RAP_KEY                         = [0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF];
        internal readonly static byte[] RAP_E1                          = [0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5];
        internal readonly static byte[] RAP_E2                          = [0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74];
        internal readonly static byte[] RAP_PBOX                        = [0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09];
        internal readonly static byte[] EDAT_IV                         = new byte[0x10];
        internal readonly static byte[] EMPTY                           = new byte[0x10];
    }
}