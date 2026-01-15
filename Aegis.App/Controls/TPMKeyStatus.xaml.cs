using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Controls;

namespace Aegis.App.Controls
{
    public partial class TPMKeyStatus : UserControl, INotifyPropertyChanged
    {
        private string _tooltipText = "No key loaded";
        public string TooltipText
        {
            get => _tooltipText;
            private set
            {
                if (_tooltipText != value)
                {
                    _tooltipText = value;
                    OnPropertyChanged(nameof(TooltipText));
                }
            }
        }

        public TPMKeyStatus()
        {
            InitializeComponent();
            Visibility = System.Windows.Visibility.Collapsed;
        }

        public async Task ShowKeyStatusAsync()
        {
            await System.Threading.Tasks.Task.Run(LoadKeyStatus);
            Dispatcher.Invoke(() =>
            {
                DataContext = this;
                Visibility = System.Windows.Visibility.Visible;
            });
        }

        private void LoadKeyStatus()
        {
            try
            {
                // CHANGE THIS NAME TO YOUR ACTUAL KEY NAME
                using var key = CngKey.Open(
                    "Aegis_ECDH_P384",
                    CngProvider.MicrosoftPlatformCryptoProvider);

                bool isTpm =
                    key.Provider.Provider.Equals(
                        "Microsoft Platform Crypto Provider",
                        System.StringComparison.OrdinalIgnoreCase);

                using var ecdsa = new ECDsaCng(key);
                byte[] pub = ecdsa.ExportSubjectPublicKeyInfo();

                using var sha = SHA256.Create();
                byte[] hash = sha.ComputeHash(pub);

                string hex = Convert.ToHexString(hash).ToLowerInvariant();

                TooltipText = new StringBuilder()
                    .AppendLine("TPM-backed ECDSA-P384 Key")
                    .AppendLine(isTpm ? "Provider: TPM (VBS/VTL1)" : "Provider: Software")
                    .AppendLine()
                    .Append("Thumbprint:\n")
                    .Append(hex)
                    .ToString();
            }
            catch
            {
                TooltipText = "TPM key not available";
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}



