using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.PcrUtils;
using Aegis.App.TPM;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using Aegis.App.Registration;
using Aegis.App.Session;

namespace Aegis.App.Pages
{
    /// <summary>
    /// Interaction logic for EnterRecoveryKey.xaml
    /// </summary>
    public partial class EnterRecoveryKey : Window
    {
        private readonly string _username;
        public EnterRecoveryKey(string username)
        {
            InitializeComponent();
            _username = username;
        }

        private void Recover_Click(object sender, RoutedEventArgs e)
        {
            using var keyStore = new IKeyStore(_username);
            int len;
            var secureKeyBytes = PinRecoveryKey(RecoveryKeyBox.Text, out len);
            TpmNvCounter counter = new TpmNvCounter(OpenTpm.CreateTpm2(), _username, PcrSelection.Pcrs);
            var recoveryKey = MasterKeyManager.RecoverAndRotateRecoveryKey(secureKeyBytes, len, keyStore.LoadKeyBlob(), counter, out var masterKey);

            RecoveryKey page = new RecoveryKey(recoveryKey.Value);
            page.ShowDialog();

            recoveryKey.Dispose();

            CryptoSession session = new CryptoSession(masterKey);

        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {

        }

        private void UseTotp_Click(object sender, RoutedEventArgs e)
        {

        }

            /// <summary>
            /// Converts a recovery key string into unmanaged pinned memory and returns the pointer.
            /// Caller is responsible for freeing it with FreeRecoveryKey.
            /// </summary>
            /// <param name="recoveryKey">The user-visible recovery key</param>
            /// <param name="keyLength">Output length in bytes of the key</param>
            /// <returns>IntPtr pointing to the unmanaged memory</returns>
            public static IntPtr PinRecoveryKey(string recoveryKey, out int keyLength)
            {
                if (string.IsNullOrEmpty(recoveryKey))
                    throw new ArgumentNullException(nameof(recoveryKey));

                // Convert string to bytes securely (UTF-8)
                byte[] keyBytes = Encoding.UTF8.GetBytes(recoveryKey);
                keyLength = keyBytes.Length;

                // Allocate unmanaged memory
                IntPtr ptr = Marshal.AllocHGlobal(keyLength);

                // Copy bytes into unmanaged memory
                Marshal.Copy(keyBytes, 0, ptr, keyLength);

                // Zero managed copy immediately
                CryptographicOperations.ZeroMemory(keyBytes);

                return ptr;
            }

            /// <summary>
            /// Frees the unmanaged memory and zeroes it
            /// </summary>
            public static void FreeRecoveryKey(IntPtr ptr, int keyLength)
            {
                if (ptr == IntPtr.Zero) return;

                try
                {
                    unsafe
                    {
                        byte* p = (byte*)ptr.ToPointer();
                        for (int i = 0; i < keyLength; i++)
                            p[i] = 0;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }

}
