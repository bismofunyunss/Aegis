using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Aegis.App.Vault.VaultEntry
{
    public static class VaultSerialization
    {
        /// <summary>
        /// Serialize the in-memory vault to a MemoryStream.
        /// </summary>
        public static MemoryStream Serialize()
        {
            var ms = new MemoryStream();

            JsonSerializer.Serialize(
                ms,
                VaultState.Items,
                new JsonSerializerOptions { WriteIndented = false }
            );

            ms.Position = 0;
            return ms;
        }

        public static void Deserialize(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            stream.Position = 0;

            var items = JsonSerializer.Deserialize<List<VaultEntry>>(stream)
                        ?? new List<VaultEntry>();

            VaultState.Items.Clear();
            foreach (var item in items)
                VaultState.Items.Add(item);
        }


        /// <summary>
        /// Add an entry to the in-memory vault.
        /// </summary>
        public static void AddEntry(VaultEntry entry)
        {
            if (entry == null)
                throw new ArgumentNullException(nameof(entry));

            VaultState.Items.Add(entry);
            VaultState.IsDirty = true;
        }


        /// <summary>
        /// Get a read-only view of the vault entries.
        /// </summary>
        public static IReadOnlyList<VaultEntry> GetEntries()
        {
            return VaultState.Items;
        }

        /// <summary>
        /// Clear the vault in memory.
        /// </summary>
        public static void Clear()
        {
            VaultState.Items.Clear();
            VaultState.IsDirty = false;
        }


        public static System.Collections.ObjectModel.ObservableCollection<VaultEntry> Items { get; }
            = new();
    }

    public class VaultEntry
    {
        public string Account { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Notes { get; set; } = string.Empty;
    }
}