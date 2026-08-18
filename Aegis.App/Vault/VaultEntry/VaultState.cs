using System.Collections.ObjectModel;

namespace Aegis.App.Vault.VaultEntry;

internal static class VaultState
{
    // Use VaultEntry instead of VaultItem
    internal static ObservableCollection<VaultEntry> Items { get; } = new ObservableCollection<VaultEntry>();
    internal static bool IsDirty { get; set; }
}