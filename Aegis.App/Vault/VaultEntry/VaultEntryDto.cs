using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.App.Vault.VaultEntry
{
    public sealed class VaultEntryDto
    {
        public string Account { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;

        public byte[] Password { get; set; } =
            [];

        public byte[] Notes { get; set; } =
            [];
    }
}
