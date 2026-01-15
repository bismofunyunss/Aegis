using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Vault.VaultEntry
{
    public static class VaultConstants
    {
        public const string VaultFileName = "Vault.aegis";
        public static readonly byte[] Signature =
            "AEGIS_VAULT_V1"u8.ToArray();

        public const string version = "1.0";
    }

}
