using System;
using System.Collections.Generic;
using System.Text;
using Tpm2Lib;

namespace Aegis.Tpm
{
    internal class OpenTpm
    {
        public static Tpm2 OpenTPM()
        {
            var device = new TbsDevice();
            device.Connect();

            var tpm = new Tpm2(device);

            return tpm;
        }
    }
}
