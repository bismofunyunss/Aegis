using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Threading;
namespace Aegis.App.Helpers
{
    internal static class HelperMethods
    {
        internal static byte[] Combine(params byte[][] arrays)
        {
            int length = 0;
            foreach (var arr in arrays) length += arr.Length;

            byte[] result = new byte[length];
            int offset = 0;
            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            return result;
        }

        public static async Task<byte[]> ReadExactAsync(Stream s, int length)
        {
            var buffer = new byte[length];
            var read = 0;
            while (read < length)
            {
                var n = await s.ReadAsync(buffer, read, length - read);
                if (n == 0) throw new EndOfStreamException();
                read += n;
            }

            return buffer;
        }
    }
}
