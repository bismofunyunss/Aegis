using System.Runtime.InteropServices;
using System.Security;

namespace Aegis.App;

public static class PasswordUtilities
{
    // ================================
    // 1️⃣ Entropy only (live feedback)
    // ================================
    public static unsafe double ComputeEntropyOnly(SecureString password)
    {
        if (password == null || password.Length == 0)
            return 0;

        IntPtr ptr = IntPtr.Zero;

        try
        {
            ptr = Marshal.SecureStringToGlobalAllocUnicode(password);
            Span<char> pwd = new Span<char>((void*)ptr, password.Length);

            double entropy = 0;

            for (int i = 0; i < pwd.Length; i++)
            {
                char c = pwd[i];

                if (char.IsWhiteSpace(c))
                    return 0;

                if (char.IsUpper(c)) entropy += Math.Log2(26);
                else if (char.IsLower(c)) entropy += Math.Log2(26);
                else if (char.IsDigit(c)) entropy += Math.Log2(10);
                else if (char.IsSymbol(c) || char.IsPunctuation(c)) entropy += Math.Log2(32);
                else entropy += Math.Log2(32);
            }

            return entropy;
        }
        finally
        {
            if (ptr != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
        }
    }

    // =================================
    // 2️⃣ Policy validation (no entropy)
    // =================================
    public static unsafe bool ValidatePasswordPolicy(
        SecureString password,
        SecureString confirmPassword)
    {
        if (password == null || confirmPassword == null)
            return false;

        if (password.Length != confirmPassword.Length ||
            password.Length < 12 ||
            password.Length > 64)
            return false;

        IntPtr pwdPtr = IntPtr.Zero;
        IntPtr confirmPtr = IntPtr.Zero;

        try
        {
            pwdPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
            confirmPtr = Marshal.SecureStringToGlobalAllocUnicode(confirmPassword);

            int len = password.Length;
            Span<char> pwd = new Span<char>((void*)pwdPtr, len);
            Span<char> confirm = new Span<char>((void*)confirmPtr, len);

            bool mismatch = false;
            bool hasUpper = false;
            bool hasLower = false;
            bool hasDigit = false;
            bool hasSymbol = false;

            for (int i = 0; i < len; i++)
            {
                char c = pwd[i];

                mismatch |= c != confirm[i];

                if (char.IsWhiteSpace(c))
                    return false;

                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else if (char.IsSymbol(c) || char.IsPunctuation(c)) hasSymbol = true;
            }

            if (mismatch)
                return false;

            return hasUpper && hasLower && hasDigit && hasSymbol;
        }
        finally
        {
            if (pwdPtr != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(pwdPtr);
            if (confirmPtr != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(confirmPtr);
        }
    }

    // ==================================================
    // 3️⃣ Final validation + entropy (submit-time only)
    // ==================================================
    public static double ValidateAndComputeEntropy(
        SecureString password,
        SecureString confirmPassword)
    {
        if (!ValidatePasswordPolicy(password, confirmPassword))
            throw new SecurityException("Password policy violation");

        return ComputeEntropyOnly(password);
    }

    // ==========================================
    // 4️⃣ Constant-time SecureString comparison
    // ==========================================
    public static unsafe bool SecureEquals(
        SecureString a,
        SecureString b)
    {
        if (a == null || b == null || a.Length != b.Length)
            return false;

        IntPtr pa = IntPtr.Zero;
        IntPtr pb = IntPtr.Zero;

        try
        {
            pa = Marshal.SecureStringToGlobalAllocUnicode(a);
            pb = Marshal.SecureStringToGlobalAllocUnicode(b);

            Span<char> sa = new Span<char>((void*)pa, a.Length);
            Span<char> sb = new Span<char>((void*)pb, b.Length);

            bool diff = false;
            for (int i = 0; i < sa.Length; i++)
                diff |= sa[i] != sb[i];

            return !diff;
        }
        finally
        {
            if (pa != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(pa);
            if (pb != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(pb);
        }
    }
}