using System.Collections.ObjectModel;

namespace Aegis.App.Vault.VaultEntry;

public static class VaultState
{
    // Use VaultEntry instead of VaultItem
    public static ObservableCollection<VaultEntry> Items { get; } = new ObservableCollection<VaultEntry>();
    public static bool IsDirty { get; set; }
}