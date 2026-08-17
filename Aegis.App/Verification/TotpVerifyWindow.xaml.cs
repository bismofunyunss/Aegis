using Aegis.App.IO;
using OtpNet;
using QRCoder;
using System.Drawing;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using Aegis.App.Crypto;

namespace Aegis.App.Verification;

public partial class TotpVerifyWindow
{
    private CancellationTokenSource? _lockoutCts;
    private readonly SoftwareKeyStore _store;
    private const int MaxAttempts = 5;
    private readonly byte[] _rawTotpSecret;

    public TotpVerifyWindow(string username, byte[] rawTotpSecret = null)
    {
        InitializeComponent();

        _store = new SoftwareKeyStore(Folders.GetUserFolder(username));

        if (rawTotpSecret != null)
        {
            // Registration: show QR
            _rawTotpSecret = rawTotpSecret;
            string secretBase32 = Base32Encoding.ToString(_rawTotpSecret);
            GenerateQrCode("Aegis", username, secretBase32);
        }
        else
        {
            // Login: load secret from keystore, hide QR
            _rawTotpSecret = _store.LoadTotpSecret(out _);
            QRCodeImage.Visibility = Visibility.Collapsed;
            this.Height -= 175;
        }

        UpdateStatus();
    }

    private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        _lockoutCts?.Cancel();
    }

    private async void StartLockoutMonitor(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            UpdateStatus();

            // Refresh every second
            try
            {
                await Task.Delay(1000, token);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private void UpdateStatus()
    {
        var snapshot = _store.GetLockoutSnapshot();

        if (snapshot.LockedUntilUtc is { } until && DateTime.UtcNow < until)
        {
            ConfirmButton.IsEnabled = false;
            int seconds = (int)(until - DateTime.UtcNow).TotalSeconds;
            StatusText.Text = $"Locked out for {seconds} second{(seconds != 1 ? "s" : "")}";
            StatusText.Visibility = Visibility.Visible;
        }
        else
        {
            ConfirmButton.IsEnabled = true;
            int remaining = MaxAttempts - snapshot.Failures;
            StatusText.Text = $"Attempts remaining: {remaining}";
            StatusText.Visibility = Visibility.Visible;
        }
    }

    private void ConfirmButton_Click(object sender, RoutedEventArgs e)
    {
        string code = new(CodeTextBox.Text.Where(char.IsDigit).ToArray());
        if (code.Length != 6) return;

        try
        {
            _store.Lockout.EnsureNotLocked();

            // Use the raw secret passed in constructor
            byte[] secret = _rawTotpSecret;
            long lastStep = _store._store.Totp?.LastUsedStep ?? -1;

            var totp = new Totp(secret);
            if (!totp.VerifyTotp(code, out long step, new VerificationWindow(previous: 1, future: 1)))
            {
                _store.Lockout.Fail();
                UpdateStatus();
                return;
            }

            if (step <= lastStep)
            {
                _store.Lockout.Fail();
                throw new SecurityException("Replay attack detected.");
            }

            _store.UpdateLastTotpStep(step);
            _store.Lockout.Success();

            DialogResult = true;
            Close();
        }
        catch (SecurityException ex)
        {
            StatusText.Text = ex.Message;
            StatusText.Visibility = Visibility.Visible;
            UpdateStatus();
        }
    }

    public void GenerateQrCode(string issuer, string username, string secretBase32)
    {
        string otpauth = $"otpauth://totp/{issuer}:{username}?secret={secretBase32}&issuer={issuer}&digits=6&period=30";

        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
        using var qr = new QRCode(data);
        using Bitmap bmp = qr.GetGraphic(20);

        QRCodeImage.Source = BitmapToImageSource(bmp);
        QRCodeImage.Visibility = Visibility.Visible;
    }

    private static BitmapImage BitmapToImageSource(Bitmap bitmap)
    {
        using var ms = new MemoryStream();
        bitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
        ms.Position = 0;

        var img = new BitmapImage();
        img.BeginInit();
        img.CacheOption = BitmapCacheOption.OnLoad;
        img.StreamSource = ms;
        img.EndInit();
        img.Freeze();
        return img;
    }
}









