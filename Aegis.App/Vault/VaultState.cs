using Aegis.App.Vault.VaultEntry;
using System.Collections.ObjectModel;

namespace Aegis.App.Vault;

public static class VaultState
{
    // Use VaultEntry instead of VaultItem
    public static ObservableCollection<SecureVaultEntry> Items { get; } = new ObservableCollection<SecureVaultEntry>();
    public static bool IsDirty { get; set; }
}