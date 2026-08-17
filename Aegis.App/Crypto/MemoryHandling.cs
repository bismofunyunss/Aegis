using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace Aegis.App.Crypto;

internal static class MemoryHandling
{
    internal static class NativeMemory
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualUnlock(IntPtr lpAddress, UIntPtr dwSize);
    }

    /// <summary>
    ///     Zeroes one or more byte arrays in memory.
    /// </summary>
    /// <param name="buffers">One or more byte arrays to zero.</param>
    public static void Clear(params byte[][] buffers)
    {
        if (buffers == null) return;

        foreach (var buffer in buffers)
        {
            if (buffer == null) continue;
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    ///     Zeroes multiple Span<byte> buffers in memory.
    /// </summary>
    public static void Clear(Span<byte> buffers)
    {
        if (buffers == null) return;

        foreach (var buffer in buffers) CryptographicOperations.ZeroMemory([buffer]);
    }

    /// <summary>
    /// Securely clears a char array from memory.
    /// </summary>
    /// <param name="buffer">The char array to clear.</param>
    public static unsafe void Clear(char[] buffer)
    {
        if (buffer == null) return;

        fixed (char* ptr = buffer)
        {
            Span<char> span = new Span<char>(ptr, buffer.Length);
            Clear(span);
        }
    }

    /// <summary>
    /// Securely clears a Span<char> from memory.
    /// </summary>
    /// <param name="span">The span to clear.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void Clear(Span<char> span)
    {
        // Use CryptographicOperations.ZeroMemory which is guaranteed not to be optimized away
        MemoryMarshal.AsBytes(span).Clear();
    }

    /// <summary>
    /// Clears multiple char arrays safely.
    /// </summary>
    /// <param name="buffers">Char arrays to clear.</param>
    public static void Clear(params char[][] buffers)
    {
        if (buffers == null) return;
        foreach (var buffer in buffers)
        {
            Clear(buffer);
        }
    }
}

public sealed class SecureRecoveryKey : IDisposable
{
    private byte[] _key;
    public SecureRecoveryKey(byte[] key) => _key = key ?? throw new ArgumentNullException(nameof(key));
    public byte[] Value => _key;

    public void Dispose()
    {
        if (_key != null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null!;
        }
    }
}


/// <summary>
///     Securely stores a master key in unmanaged memory with page locking.
///     Automatically zeros memory on dispose.
/// </summary>
public sealed class SecureMasterKey : IDisposable
{
    private IntPtr _ptr = IntPtr.Zero;
    private int _length;
    private bool _disposed;

    public int Length => _length;

    /// <summary>
    /// Indicates whether the master key is allocated and not disposed.
    /// </summary>
    public bool IsInitialized => !_disposed && _ptr != IntPtr.Zero && _length > 0;

    public SecureMasterKey(byte[] key)
    {
        if (key == null || key.Length == 0)
            throw new ArgumentException(nameof(key));

        _length = key.Length;
        _ptr = Marshal.AllocHGlobal(_length);
        Marshal.Copy(key, 0, _ptr, _length);
        CryptographicOperations.ZeroMemory(key);

        if (!MemoryHandling.NativeMemory.VirtualLock(_ptr, (UIntPtr)_length))
            throw new CryptographicException("VirtualLock failed.");
    }

    public void CopyKeyTo(Span<byte> destination)
    {
        EnsureAlive();
        if (destination.Length < _length)
            throw new ArgumentException("Destination too small.");
        unsafe
        {
            new ReadOnlySpan<byte>((void*)_ptr, _length).CopyTo(destination);
        }
    }

    public unsafe ReadOnlySpan<byte> GetKeySpan() => new ReadOnlySpan<byte>((void*)_ptr, _length);

    /// <summary>
    /// Derives a new key from the master key using the provided HKDF parameters.
    /// </summary>
    public byte[] DeriveKey(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        EnsureAlive();
        unsafe
        {
            var ikm = new ReadOnlySpan<byte>((void*)_ptr, _length);
            return CryptoMethods.HKDF.DeriveKey(ikm, salt, info, length);
        }
    }

    private void EnsureAlive()
    {
        if (_disposed || _ptr == IntPtr.Zero)
            throw new ObjectDisposedException(nameof(SecureMasterKey));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        var ptr = Interlocked.Exchange(ref _ptr, IntPtr.Zero);
        if (ptr != IntPtr.Zero)
        {
            unsafe
            {
                Span<byte> span = new Span<byte>((void*)ptr, _length);
                CryptographicOperations.ZeroMemory(span);
            }
            MemoryHandling.NativeMemory.VirtualUnlock(ptr, (UIntPtr)_length);
            Marshal.FreeHGlobal(ptr);
            _length = 0;
        }

        GC.SuppressFinalize(this);
    }

    ~SecureMasterKey() => Dispose();
}



internal static class AntiDebug
{ 
    public static void AssertCleanEnvironment()
    {
#if !DEBUG
    if (Debugger.IsAttached)
        throw new SecurityException("Debugger detected.");
#endif
        if (IsProfilerAttached())
            throw new SecurityException("Profiler detected.");
    }

    private static bool IsProfilerAttached()
    {
        return Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING") == "1";
    }
}

internal sealed unsafe class SecureBuffer : IDisposable
{
    private IntPtr _ptr;

    public SecureBuffer(ReadOnlySpan<byte> source)
    {
        Length = source.Length;
        _ptr = Marshal.AllocHGlobal(Length);
        source.CopyTo(new Span<byte>((void*)_ptr, Length));
    }

    public int Length { get; }

    public void Dispose()
    {
        if (_ptr != IntPtr.Zero)
        {
            CryptographicOperations.ZeroMemory(AsSpan());
            Marshal.FreeHGlobal(_ptr);
            _ptr = IntPtr.Zero;
        }
    }

    public Span<byte> AsSpan()
    {
        return new Span<byte>((void*)_ptr, Length);
    }

    public byte[] ToArrayCopy()
    {
        var tmp = new byte[Length];
        AsSpan().CopyTo(tmp);
        return tmp;
    }

}