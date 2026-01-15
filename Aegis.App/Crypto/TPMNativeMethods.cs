using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Aegis.App.Crypto
{
    internal class TPMNativeMethods
    {
        internal const string NCRYPT_PCP_PCRTABLE_PROPERTY = "PCP_PCRTABLE";

        [StructLayout(LayoutKind.Sequential)]
        internal struct PCR_SELECTION
        {
            public uint HashAlg;
            public uint SizeOfSelect;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] PcrSelect;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PCP_PCRTABLE
        {
            public uint PcrSelections;
            public PCR_SELECTION Selection;
        }

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern int NCryptSetProperty(
            SafeNCryptKeyHandle hObject,
            string pszProperty,
            byte[] pbInput,
            int cbInput,
            int dwFlags
        );
    }
}