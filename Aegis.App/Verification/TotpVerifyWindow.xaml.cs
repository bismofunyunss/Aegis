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

public partial class TotpVerifyWindow : Window
{
    private readonly IKeyStore _store;
    private readonly byte[] _rawTotpSecret;
    private const int MaxAttempts = 5;

    public TotpVerifyWindow(IKeyStore store, byte[] rawTotpSecret = null)
    {
        InitializeComponent();

        _store = store ?? throw new ArgumentNullException(nameof(store));
        _rawTotpSecret = rawTotpSecret ?? _store.LoadTotpSecret();

        if (rawTotpSecret != null)
        {
            // Registration: show QR
            string secretBase32 = Base32Encoding.ToString(_rawTotpSecret);
            GenerateQrCode("Aegis", store.Username, secretBase32);
        }
        else
        {
            // Login: hide QR
            QRCodeImage.Visibility = Visibility.Collapsed;
            this.Height -= 175;
        }

        UpdateStatus();
    }

    private void UpdateStatus()
    {
        var snapshot = _store.Lockout.GetSnapshot();

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
        string code = new string(CodeTextBox.Text.Where(char.IsDigit).ToArray());
        if (code.Length != 6) return;

        try
        {
            _store.Lockout.EnsureNotLocked();

            long lastStep = _store._store.Totp?.LastUsedStep ?? -1;
            var totp = new Totp(_rawTotpSecret);

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

            // Update last used step
            _store.UpdateTotpStep(step);
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










