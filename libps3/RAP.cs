using libps3.Cryptography;

namespace libps3
{
    public class RAP
	{
        public static byte[] RapToRif(byte[] rap)
        {
            byte[] rif = CryptoHelper.DecryptAESECB(KeyVault.RAP_KEY, rap);
            for (int round = 0; round < 5; round++)
            {
                for (int i = 0; i < 16; i++)
                {
                    int p = KeyVault.RAP_PBOX[i];
                    rif[p] ^= KeyVault.RAP_E1[p];
                }

                for (int i = 15; i > 0; i--)
                {
                    int p = KeyVault.RAP_PBOX[i];
                    int pp = KeyVault.RAP_PBOX[i - 1];
                    rif[p] ^= rif[pp];
                }

                int acum = 0;
                for (int i = 0; i < 16; i++)
                {
                    int p = KeyVault.RAP_PBOX[i];
                    byte current = (byte)(rif[p] - acum);
                    rif[p] = current;
                    if (acum != 1 || current != 255)
                    {
                        int kc = current & byte.MaxValue;
                        int ec2 = KeyVault.RAP_E2[p] & byte.MaxValue;
                        acum = (kc >= ec2) ? 0 : 1;
                    }
                    current -= KeyVault.RAP_E2[p];
                    rif[p] = current;
                }
            }

            return rif;
        }
    }
}
