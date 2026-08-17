using System.Drawing;
using System.IO;
using System.Security;
using System.Windows;
using System.Windows.Media.Imaging;
using Aegis.App.Ipc;
using Aegis.Contracts;
using QRCoder;

namespace Aegis.App.Verification;

public partial class TotpRegisterWindow : Window
{
    private readonly TotpEnrollment _enrollment;

    public TotpRegisterWindow(
        TotpEnrollment enrollment)
    {
        InitializeComponent();

        _enrollment =
            enrollment ??
            throw new ArgumentNullException(
                nameof(enrollment));

        if (string.IsNullOrWhiteSpace(
                _enrollment.EnrollmentId))
        {
            throw new ArgumentException(
                "TOTP enrollment ID is required.",
                nameof(enrollment));
        }

        if (string.IsNullOrWhiteSpace(
                _enrollment.Uri))
        {
            throw new ArgumentException(
                "TOTP enrollment URI is required.",
                nameof(enrollment));
        }

        GenerateQrCode(
            _enrollment.Uri);
    }

    private async void ConfirmButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        string code =
            new(
                CodeTextBox.Text
                    .Where(char.IsDigit)
                    .ToArray());

        if (code.Length != 6)
        {
            StatusText.Text =
                "Enter the 6-digit code.";

            StatusText.Visibility =
                Visibility.Visible;

            return;
        }

        try
        {
            ConfirmButton.IsEnabled = false;

            StatusText.Text =
                "Verifying...";

            StatusText.Visibility =
                Visibility.Visible;

            await AppServices.Core
                .ConfirmTotpEnrollmentAsync(
                    _enrollment.EnrollmentId,
                    code);

            DialogResult = true;
            Close();
        }
        catch (SecurityException ex)
        {
            StatusText.Text =
                ex.Message;

            StatusText.Visibility =
                Visibility.Visible;

            CodeTextBox.Clear();
            CodeTextBox.Focus();
        }
        catch (Exception)
        {
            StatusText.Text =
                "Unable to verify the authentication code.";

            StatusText.Visibility =
                Visibility.Visible;
        }
        finally
        {
            if (IsVisible)
            {
                ConfirmButton.IsEnabled = true;
            }
        }
    }

    private void GenerateQrCode(
        string otpauthUri)
    {
        using var generator =
            new QRCodeGenerator();

        using var data =
            generator.CreateQrCode(
                otpauthUri,
                QRCodeGenerator.ECCLevel.Q);

        using var qr =
            new QRCode(data);

        using Bitmap bmp =
            qr.GetGraphic(20);

        QRCodeImage.Source =
            BitmapToImageSource(bmp);

        QRCodeImage.Visibility =
            Visibility.Visible;
    }

    private static BitmapImage BitmapToImageSource(
        Bitmap bitmap)
    {
        using var ms =
            new MemoryStream();

        bitmap.Save(
            ms,
            System.Drawing.Imaging.ImageFormat.Png);

        ms.Position = 0;

        var image =
            new BitmapImage();

        image.BeginInit();

        image.CacheOption =
            BitmapCacheOption.OnLoad;

        image.StreamSource =
            ms;

        image.EndInit();

        image.Freeze();

        return image;
    }


}