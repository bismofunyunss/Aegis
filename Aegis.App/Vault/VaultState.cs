using System.Collections.ObjectModel;

namespace Aegis.App.Vault;

public static class VaultState
{
    // Use VaultEntry instead of VaultItem
    internal static ObservableCollection<VaultEntry.VaultEntry> Items { get; } = [];
    public static bool IsDirty { get; set; }
}