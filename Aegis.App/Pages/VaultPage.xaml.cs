using Aegis.App.Crypto;
using Aegis.App.Vault.VaultEntry;
using System.Windows;
using System.Windows.Controls;

namespace Aegis.App.Pages;

public partial class VaultPage : Page
{
    public VaultPage()
    {
        InitializeComponent();

        DataGridVault.ItemsSource =
            Vault.VaultState.Items;
    }


    // ============================================================
    // ADD ENTRY
    // ============================================================

    private void AddEntry_Click(
        object sender,
        RoutedEventArgs e)
    {
        var entry =
            new VaultEntry();

        Vault.VaultState.Items.Add(
            entry);

        Vault.VaultState.IsDirty = true;

        DataGridVault.SelectedItem =
            entry;

        DataGridVault.ScrollIntoView(
            entry);
    }


    // ============================================================
    // DELETE ENTRY
    // ============================================================

    private void DeleteEntry_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (sender is Button button &&
            button.DataContext is Vault.VaultEntry.VaultEntry entry)
        {
            Vault.VaultState.Items.Remove(
                entry);

            Vault.VaultState.IsDirty = true;
        }
    }


    // ============================================================
    // SAVE VAULT
    // ============================================================

    private async void SaveButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        try
        {
            // Make sure any active DataGrid edit is committed.
            DataGridVault.CommitEdit(
                DataGridEditingUnit.Cell,
                true);

            DataGridVault.CommitEdit(
                DataGridEditingUnit.Row,
                true);

            if (Vault.VaultState.Items.Count == 0)
            {
                MessageBox.Show(
                    "The vault contains no entries.",
                    "Nothing to Save",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                return;
            }

            await VaultService.SaveVaultAsync();

            MessageBox.Show(
                "Vault saved successfully.",
                "Vault",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            // User cancelled the operation.
        }
        catch (Exception ex)
        {
            FileLogger.Log(ex,
                "VAULT UI: Vault save failed.",
                ClientSessionManager.Current.Username);

            MessageBox.Show(
                "There was an error while saving vault.",
                "Vault Save Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }
}