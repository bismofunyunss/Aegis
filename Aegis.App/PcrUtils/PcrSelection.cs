using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Tpm2Lib;

namespace Aegis.App.PcrUtils
{
    internal class PcrSelection()
    {
        public static uint[] Pcrs = new uint[] { 0, 2, 4, 7, 11 };
    }
}
