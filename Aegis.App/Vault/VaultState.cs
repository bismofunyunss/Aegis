using System.Collections.ObjectModel;

namespace Aegis.App.Vault;

public static class VaultState
{
    // Use VaultEntry instead of VaultItem
    public static ObservableCollection<VaultEntry.VaultEntry> Items { get; } = new ObservableCollection<VaultEntry.VaultEntry>();
    public static bool IsDirty { get; set; }
}