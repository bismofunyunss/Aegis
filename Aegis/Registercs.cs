using Aegis.Registration;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;

namespace Aegis
{
    public partial class RegisterPage : UserControl
    {
        public RegisterPage()
        {
            InitializeComponent();
        }

        private static bool CheckPasswordValidity(IReadOnlyCollection<char> password,
            IReadOnlyCollection<char>? password2 = null)
        {
            if (password is { Count: < 22 or > 120 })
                return false;

            if (!password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit))
                return false;

            if (password.Any(char.IsWhiteSpace) || (password2 != null &&
                                                    (password2.Any(char.IsWhiteSpace) ||
                                                     !password.SequenceEqual(password2))))
                return false;

            return password.Any(char.IsSymbol) || password.Any(char.IsPunctuation);
        }

        private static void ValidateUsernameAndPassword(string userName, char[] password, char[] password2)
        {
            if (!userName.All(c => char.IsLetterOrDigit(c) || c == '_' || c == ' '))
                throw new ArgumentException(
                    "Value contains illegal characters. Valid characters are letters, digits, underscores, and spaces.",
                    nameof(userName));

            if (string.IsNullOrEmpty(userName) || userName.Length > 20)
                throw new ArgumentException("Invalid username.", nameof(userName));

            if (password == Array.Empty<char>())
                throw new ArgumentException("Invalid password.", nameof(password));

            if (!CheckPasswordValidity(password, password2))
                throw new Exception(
                    "Password must contain between 22 and 120 characters. It also must include:" +
                    " 1.) At least one uppercase letter." +
                    " 2.) At least one lowercase letter." +
                    " 3.) At least one number." +
                    " 4.) At least one special character." +
                    " 5.) Must not contain any spaces." +
                    " 6.) Both passwords must match.");
        }

        public static char[] GetPasswordBuffer(MaskedTextBox textBox)
        {
            if (textBox == null)
                throw new ArgumentNullException(nameof(textBox));

            var buffer = new char[textBox.TextLength];
            textBox.Text.CopyTo(0, buffer, 0, buffer.Length);

            return buffer; // CALLER MUST ZERO THIS
        }


        private async void registerBtn_Click(object sender, EventArgs e)
        {
            char[] password = GetPasswordBuffer(pwBox);
            string userName = userTxt.Text;

            try
            {
                UserRegistrationService service = new UserRegistrationService();
                var store = await service.CreateUserAsync(userName, password);
            }
            finally
            {
                // ALWAYS wipe password buffer
                CryptographicOperations.ZeroMemory(
                    System.Runtime.InteropServices.MemoryMarshal.AsBytes(password.AsSpan())
                );
            }
        }
    }

}
