using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.SecureStringUtil
{
    internal class ToBytes
    {
        public static byte[] ToUtf8Bytes(SecureString secureString)
        {
            if (secureString == null)
                throw new ArgumentNullException(nameof(secureString));

            IntPtr ptr = IntPtr.Zero;
            try
            {
                // Convert SecureString → unmanaged Unicode
                ptr = Marshal.SecureStringToGlobalAllocUnicode(secureString);

                // Copy chars into managed string briefly
                var str = Marshal.PtrToStringUni(ptr)
                          ?? throw new InvalidOperationException();

                // Convert to UTF-8 bytes
                return System.Text.Encoding.UTF8.GetBytes(str);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        public static void ZeroBytes(byte[] buffer)
        {
            if (buffer == null) return;
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
