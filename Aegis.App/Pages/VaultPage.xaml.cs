using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Vault.VaultEntry;
using System.Collections.ObjectModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using static Aegis.App.Pages.FileEncryptionPage;
using static Aegis.App.ParallelCtrEncryptor;

namespace Aegis.App.Pages;

public partial class VaultPage : Page
{
    public ObservableCollection<VaultEntry> VaultItems { get; } = new ObservableCollection<VaultEntry>();

    public VaultPage()
    {
        InitializeComponent();
        VaultItems = VaultState.Items;
        DataGridVault.ItemsSource = VaultItems;
        DataContext = this;
    }

        private void AddEntry_Click(object sender, RoutedEventArgs e)
        {
            VaultItems.Add(new VaultEntry());
        }

        private void DeleteEntry_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is VaultEntry entry)
            {
                VaultItems.Remove(entry);
            }
        }


        private async void SaveButton_Click(object sender, RoutedEventArgs e)
        {
        await VaultService.SaveVaultAsync(Session.Session.SessionManager.User.Username);
    }
}


