using System.IO;
using System.Security.Cryptography;
using System.Text;
using ABI.Windows.Devices.Bluetooth.Advertisement;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.IO;
using Microsoft.Win32;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Aegis.App.Crypto;

internal static class KeyWrap
{
    /// <summary>
    ///     AES Key Wrap (RFC 5649) wrapper.
    /// </summary>
    public static byte[] AesKeyWrap(byte[] kek, byte[] keyToWrap)
    {
        var engine = new AesWrapPadEngine(); // RFC 5649
        engine.Init(true, new KeyParameter(kek)); // true = wrap
        return engine.Wrap(keyToWrap, 0, keyToWrap.Length);
    }

    /// <summary>
    ///     AES Key Unwrap (RFC 5649) unwrapper.
    /// </summary>
    public static byte[] AesKeyUnwrap(byte[] kek, byte[] wrappedKey)
    {
        var engine = new AesWrapPadEngine(); // RFC 5649
        engine.Init(false, new KeyParameter(kek)); // false = unwrap
        return engine.Unwrap(wrappedKey, 0, wrappedKey.Length);
    }
}