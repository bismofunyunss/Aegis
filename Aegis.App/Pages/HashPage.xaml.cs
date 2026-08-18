using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using Aegis.App.Crypto;
using Aegis.App.Interfaces;
using Microsoft.Win32;

namespace Aegis.App.Pages;

/// <summary>
///     Interaction logic for HashPage.xaml
/// </summary>
public partial class HashPage : Page, IWindowResizablePage
{
    private string selectedFilePath;

    public HashPage()
    {
        InitializeComponent();
    }

    public double DesiredWidth => 975; // width for this page
    public double DesiredHeight => 530; // height for this page

    private void OpenFileButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Title = "Select File to Hash",
            Filter = "All Files (*.*)|*.*"
        };

        var result = openFileDialog.ShowDialog();

        if (result == true)
        {
            selectedFilePath = openFileDialog.FileName;
            // Optional: show file name somewhere (maybe in the button or a label)
            MessageBox.Show($"File selected:\n{selectedFilePath}", "File Selected", MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    public void FileDropZone_Drop(object sender, DragEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            if (!e.Data.GetDataPresent(DataFormats.FileDrop))
                return;

            var files = (string[])e.Data.GetData(DataFormats.FileDrop);

            if (files.Length == 0)
                return;

            var file = files[0];

            var info = new FileInfo(file);

            if (!info.Exists)
                return;

            if (info.Length == 0)
            {
                MessageBox.Show(
                    "File is empty.",
                    "Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);

                return;
            }

            selectedFilePath = info.Name;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void FileDropZone_DragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
            e.Effects = DragDropEffects.Copy;
        else
            e.Effects = DragDropEffects.None;

        e.Handled = true;
    }

    private void ComputeHashButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(selectedFilePath))
        {
            MessageBox.Show("Please select a file first.", "No File", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (HashAlgorithmComboBox.SelectedItem is not ComboBoxItem selectedItem)
            return;

        var algorithm = selectedItem.Content.ToString();

        try
        {
            var hash = ComputeFileHash(selectedFilePath, algorithm);
            HashOutputTextBox.Text = hash;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error computing hash:\n{ex.Message}", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private string ComputeFileHash(string filePath, string algorithm)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found", filePath);

        // MD5 / SHA1 / SHA256 / SHA384 / SHA512
        switch (algorithm.ToUpper())
        {
            case "MD5":
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA-1":
                using (var sha1 = SHA1.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha1.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA-256":
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA-384":
                using (var sha384 = SHA384.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha384.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA-512":
                using (var sha512 = SHA512.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha512.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA3-256":
                using (var sha3256 = SHA3_256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha3256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA3-384":
                using (var sha3384 = SHA3_384.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha3384.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            case "SHA3-512":
                using (var sha3512 = SHA3_512.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha3512.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }

            default:
                throw new NotSupportedException($"Hash algorithm {algorithm} is not supported.");
        }
    }
}