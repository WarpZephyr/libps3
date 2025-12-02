using System;

namespace libps3.Helpers
{
    internal class StaticRandom
    {
        [ThreadStatic]
        internal static Random Random;

        static StaticRandom()
        {
            Random = new Random();
        }
    }
}
