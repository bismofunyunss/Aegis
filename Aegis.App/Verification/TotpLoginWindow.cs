using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using Aegis.App.Crypto;
using Aegis.App.Ipc;

namespace Aegis.App.Verification;

internal partial class TotpLoginWindow : Window
{
    private readonly string _authenticationId;

private bool _isVerifying;
    private bool _completed;


    public TotpLoginWindow(
        string authenticationId)
    {
        if (string.IsNullOrWhiteSpace(authenticationId))
            throw new ArgumentException(
                "Authentication ID is required.",
                nameof(authenticationId));

        InitializeComponent();

        _authenticationId =
            authenticationId;

        Loaded +=
            TotpLoginWindow_Loaded;
    }


    // =========================================================
    // WINDOW
    // =========================================================

    private void TotpLoginWindow_Loaded(
        object sender,
        RoutedEventArgs e)
    {
        Activate();

        CodeTextBox.Focus();
    }


    // =========================================================
    // CODE INPUT
    // =========================================================

    private void CodeTextBox_PreviewTextInput(
        object sender,
        TextCompositionEventArgs e)
    {
        e.Handled =
            !IsDigitsOnly(e.Text);
    }


    private void CodeTextBox_TextChanged(
        object sender,
        System.Windows.Controls.TextChangedEventArgs e)
    {
        string text =
            CodeTextBox.Text;

        if (string.IsNullOrEmpty(text))
            return;

        string digits =
            ExtractDigits(text);

        if (!string.Equals(
                text,
                digits,
                StringComparison.Ordinal))
        {
            int caret =
                Math.Min(
                    CodeTextBox.CaretIndex,
                    digits.Length);

            CodeTextBox.Text =
                digits;

            CodeTextBox.CaretIndex =
                caret;

            return;
        }

        if (digits.Length == 6 &&
            !_isVerifying)
        {
            ConfirmButton.Focus();
        }
    }


    private void CodeTextBox_KeyDown(
        object sender,
        KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;

            if (!_isVerifying &&
                CodeTextBox.Text.Length == 6)
            {
                _ = VerifyAsync();
            }
        }

        else if (e.Key == Key.Escape)
        {
            e.Handled = true;

            if (!_isVerifying)
            {
                CancelLogin();
            }
        }
    }


    // =========================================================
    // VERIFY
    // =========================================================

    private async void ConfirmButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        await VerifyAsync();
    }


    private async Task VerifyAsync()
    {
        if (_isVerifying)
            return;

        string code =
            CodeTextBox.Text.Trim();

        if (code.Length != 6 ||
            !IsDigitsOnly(code))
        {
            ShowStatus(
                "Enter the 6-digit authentication code.",
                false);

            CodeTextBox.Focus();

            return;
        }

        _isVerifying = true;

        SetBusy(true);

        try
        {
            bool success =
                await AppServices.Core
                    .ConfirmLoginTotpAsync(
                        _authenticationId,
                        code);

            if (!success)
            {
                ShowStatus(
                    "The authentication code is invalid or has expired.",
                    false);

                CodeTextBox.Clear();
                CodeTextBox.Focus();

                return;
            }

            // =============================================
            // TOTP SUCCESSFUL
            // =============================================

            _completed = true;

            DialogResult = true;
        }
        catch (SecurityException)
        {
            ShowStatus(
                "The authentication code is invalid or has expired.",
                false);

            CodeTextBox.Clear();
            CodeTextBox.Focus();
        }
        catch (TimeoutException)
        {
            ShowStatus(
                "The authentication service did not respond. Please try again.",
                false);
        }
        catch (CryptographicException)
        {
            ShowStatus(
                "Authentication could not be completed.",
                false);
        }
        catch (Exception)
        {
            ShowStatus(
                "Authentication could not be completed. Please try again.",
                false);
        }
        finally
        {
            SetBusy(false);

            _isVerifying = false;
        }
    }


    // =========================================================
    // CANCEL
    // =========================================================

    private void CancelButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_isVerifying)
            return;

        CancelLogin();
    }


    private void CancelLogin()
    {
        if (_completed)
            return;

        DialogResult = false;
    }


    // =========================================================
    // UI STATE
    // =========================================================

    private void SetBusy(
        bool busy)
    {
        ConfirmButton.IsEnabled =
            !busy;

        CancelButton.IsEnabled =
            !busy;

        CodeTextBox.IsEnabled =
            !busy;

        if (busy)
        {
            ConfirmButton.Content =
                "Verifying...";

            ShowStatus(
                "Verifying authentication code...",
                true);
        }
        else
        {
            ConfirmButton.Content =
                "Verify & Continue";
        }
    }


    private void ShowStatus(
        string message,
        bool informational)
    {
        StatusText.Text =
            message;

        StatusText.Foreground =
            informational
                ? System.Windows.Media.Brushes.LightGray
                : System.Windows.Media.Brushes.LightGray;

        StatusBorder.Visibility =
            Visibility.Visible;
    }


    // =========================================================
    // VALIDATION
    // =========================================================

    private static bool IsDigitsOnly(
        string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        foreach (char c in value)
        {
            if (c < '0' || c > '9')
                return false;
        }

        return true;
    }


    private static string ExtractDigits(
        string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        Span<char> buffer =
            stackalloc char[value.Length];

        int count = 0;

        foreach (char c in value)
        {
            if (c >= '0' && c <= '9')
            {
                buffer[count++] = c;
            }
        }

        return new string(
            buffer[..count]);
    }
}

