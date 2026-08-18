using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

using Aegis.App.Core;
using Aegis.App.Crypto;
using Aegis.App.Ipc;
using Aegis.Contracts;

using Microsoft.Win32;

using Path = System.IO.Path;

namespace Aegis.App.Pages;

/// <summary>
/// Interaction logic for FileEncryptionPage.xaml
/// </summary>
public partial class FileEncryptionPage :
    Page,
    IWindowResizablePage
{
    private string _baseStatusText =
        string.Empty;

    private DispatcherTimer? _cryptoStatusTimer;

    private FileOperationResult? _currentResult;

    private CancellationTokenSource? _operationCts;

    private int _dotCount;


    public FileEncryptionPage()
    {
        InitializeComponent();
    }


    public double DesiredWidth =>
        820;


    public double DesiredHeight =>
        600;


    // =========================================================
    // OPEN FILE
    // =========================================================

    private void OpenFileButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            var dialog =
                new OpenFileDialog
                {
                    Filter =
                        "All Files (*.*)|*.*",

                    Title =
                        "Select File",

                    CheckFileExists =
                        true,

                    RestoreDirectory =
                        true
                };

            if (dialog.ShowDialog() != true)
                return;

            var file =
                dialog.FileName;

            var info =
                new FileInfo(
                    file);

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

            FileVars.LoadedFile =
                file;

            FileVars.FileOpened =
                true;

            FileVars.FileSize =
                info.Length;

            FileVars.FileExtension =
                info.Extension;

            FileVars.IsEncrypted =
                false;

            FileVars.IsDecrypted =
                false;

            _currentResult =
                null;

            UpdateFileStatusLabel();
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


    // =========================================================
    // DRAG / DROP
    // =========================================================

    public void FileDropZone_Drop(
        object sender,
        DragEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            if (!e.Data.GetDataPresent(
                    DataFormats.FileDrop))
            {
                return;
            }

            var files =
                (string[])e.Data.GetData(
                    DataFormats.FileDrop);

            if (files.Length == 0)
                return;

            var file =
                files[0];

            var info =
                new FileInfo(
                    file);

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

            FileVars.LoadedFile =
                file;

            FileVars.FileOpened =
                true;

            FileVars.FileSize =
                info.Length;

            FileVars.FileExtension =
                info.Extension;

            FileVars.IsEncrypted =
                false;

            FileVars.IsDecrypted =
                false;

            _currentResult =
                null;

            UpdateFileStatusLabel();
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


    private void FileDropZone_DragOver(
        object sender,
        DragEventArgs e)
    {
        if (e.Data.GetDataPresent(
                DataFormats.FileDrop))
        {
            e.Effects =
                DragDropEffects.Copy;
        }
        else
        {
            e.Effects =
                DragDropEffects.None;
        }

        e.Handled =
            true;
    }


    // =========================================================
    // ENCRYPT
    // =========================================================

    private async void EncryptFileButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            await EncryptFileAsync();
        }
        catch (OperationCanceledException)
        {
            StatusDot.Fill =
                Brushes.Orange;

            StatusLbl.Text =
                "Encryption cancelled.";

            FileStatusLbl.Text =
                "Encryption was cancelled.";

            FileStatusLbl.Foreground =
                Brushes.Orange;
        }
        catch (CryptographicException ex)
        {
            StopCryptoStatus();

            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Encryption failed.";

            FileVars.IsEncrypted =
                false;

            MessageBox.Show(
                ex.Message,
                "Encryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (SecurityException ex)
        {
            StopCryptoStatus();

            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Security error.";

            MessageBox.Show(
                ex.Message,
                "Encryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            StopCryptoStatus();

            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Encryption failed.";

            FileVars.IsEncrypted =
                false;

            MessageBox.Show(
                ex.Message,
                "Encryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    private async Task EncryptFileAsync()
    {
        if (string.IsNullOrWhiteSpace(
                FileVars.LoadedFile))
        {
            throw new InvalidOperationException(
                "No file has been selected.");
        }

        if (!File.Exists(
                FileVars.LoadedFile))
        {
            throw new FileNotFoundException(
                "The selected file no longer exists.",
                FileVars.LoadedFile);
        }

        ToggleButtons(
            false);

        CancelOperationButton.IsEnabled =
            true;

        StatusDot.Fill =
            Brushes.LimeGreen;

        StartCryptoStatus(
            "Encrypting");

        _operationCts?.Dispose();

        _operationCts =
            new CancellationTokenSource();

        try
        {
            var result =
                await AppServices.IpcClient
                    .EncryptFileAsync(
                        FileVars.LoadedFile,
                        null,
                        _operationCts.Token);

            if (result == null)
            {
                throw new CryptographicException(
                    "Encryption returned no result.");
            }

            if (string.IsNullOrWhiteSpace(
                    result.OutputPath))
            {
                throw new CryptographicException(
                    "Encryption did not produce an output file.");
            }

            if (!File.Exists(
                    result.OutputPath))
            {
                throw new FileNotFoundException(
                    "Encrypted output file was not created.",
                    result.OutputPath);
            }

            _currentResult =
                result;

            FileVars.IsEncrypted =
                true;

            FileVars.IsDecrypted =
                false;

            ProgressBar.Value =
                100;

            ProgressPanel.Visibility =
                Visibility.Visible;

            StatusLbl.Text =
                "File encrypted successfully.";

            FileStatusLbl.Text =
                "File encrypted successfully.";

            FileStatusLbl.Foreground =
                Brushes.LimeGreen;

            MessageBox.Show(
                "File encrypted successfully.\n\n" +
                "Click Save to export it.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            StopCryptoStatus();

            CancelOperationButton.IsEnabled =
                false;

            ToggleButtons(
                true);

            _operationCts?.Dispose();

            _operationCts =
                null;

            if (_currentResult == null)
            {
                ProgressBar.Value =
                    0;

                ProgressPanel.Visibility =
                    Visibility.Collapsed;
            }

            StatusDot.Fill =
                Brushes.DeepSkyBlue;
        }
    }


    // =========================================================
    // DECRYPT
    // =========================================================

    private async void DecryptFileButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            await DecryptFileAsync();
        }
        catch (OperationCanceledException)
        {
            StatusDot.Fill =
                Brushes.Orange;

            StatusLbl.Text =
                "Decryption cancelled.";

            FileStatusLbl.Text =
                "Decryption was cancelled.";

            FileStatusLbl.Foreground =
                Brushes.Orange;
        }
        catch (CryptographicException ex)
        {
            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Decryption failed.";

            MessageBox.Show(
                ex.Message,
                "Decryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (SecurityException ex)
        {
            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Security error.";

            MessageBox.Show(
                ex.Message,
                "Decryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            StatusDot.Fill =
                Brushes.Red;

            StatusLbl.Text =
                "Decryption failed.";

            MessageBox.Show(
                ex.Message,
                "Decryption Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    private async Task DecryptFileAsync()
    {
        // =====================================================
        // VALIDATE SELECTED FILE
        // =====================================================

        if (!FileVars.FileOpened)
        {
            MessageBox.Show(
                "Please select a file first.",
                "No File Selected",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        if (string.IsNullOrWhiteSpace(
                FileVars.LoadedFile))
        {
            MessageBox.Show(
                "The selected file path is invalid.",
                "Invalid File",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        if (!File.Exists(
                FileVars.LoadedFile))
        {
            MessageBox.Show(
                "The selected file no longer exists.",
                "File Not Found",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        var fileInfo =
            new FileInfo(
                FileVars.LoadedFile);

        if (fileInfo.Length <= 0)
        {
            MessageBox.Show(
                "The selected file is empty.",
                "Invalid File",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            return;
        }

        // =====================================================
        // BEGIN DECRYPTION
        // =====================================================

        ToggleButtons(
            false);

        CancelOperationButton.IsEnabled =
            true;

        StatusDot.Fill =
            Brushes.LimeGreen;

        StartCryptoStatus(
            "Decrypting");

        _operationCts?.Dispose();

        _operationCts =
            new CancellationTokenSource();

        _currentResult =
            null;

        try
        {
            ProgressBar.Value =
                0;

            ProgressPanel.Visibility =
                Visibility.Visible;

            var result =
                await AppServices.IpcClient
                    .DecryptFileAsync(
                        FileVars.LoadedFile,
                        cancellationToken:
                            _operationCts.Token);

            if (result == null)
            {
                throw new CryptographicException(
                    "The decryption service returned no result.");
            }

            if (string.IsNullOrWhiteSpace(
                    result.OutputPath))
            {
                throw new CryptographicException(
                    "The decryption service returned an invalid output path.");
            }

            if (!File.Exists(
                    result.OutputPath))
            {
                throw new FileNotFoundException(
                    "The decrypted output file could not be found.",
                    result.OutputPath);
            }

            var outputInfo =
                new FileInfo(
                    result.OutputPath);

            if (outputInfo.Length <= 0)
            {
                throw new InvalidDataException(
                    "The decrypted output file is empty.");
            }

            _currentResult =
                result;

            FileVars.IsEncrypted =
                false;

            FileVars.IsDecrypted =
                true;

            FileVars.OriginalExtension =
                result.SuggestedExtension;

            ProgressBar.Value =
                100;

            StatusDot.Fill =
                Brushes.LimeGreen;

            StatusLbl.Text =
                "Decryption complete.";

            FileStatusLbl.Text =
                "File decrypted successfully.";

            FileStatusLbl.Foreground =
                Brushes.LimeGreen;

            MessageBox.Show(
                "File decrypted successfully.\n\n" +
                "Click Save to export it.",
                "Decryption Complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            StopCryptoStatus();

            CancelOperationButton.IsEnabled =
                false;

            ToggleButtons(
                true);

            _operationCts?.Dispose();

            _operationCts =
                null;

            if (_currentResult == null)
            {
                ProgressBar.Value =
                    0;

                ProgressPanel.Visibility =
                    Visibility.Collapsed;
            }

            StatusDot.Fill =
                Brushes.DeepSkyBlue;
        }
    }


    // =========================================================
    // CANCEL
    // =========================================================

    private void CancelOperationButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (_operationCts == null)
            return;

        _operationCts.Cancel();

        CancelOperationButton.IsEnabled =
            false;

        StatusLbl.Text =
            "Cancelling...";
    }


    // =========================================================
    // SAVE
    // =========================================================

    private async void SaveFileButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (!ClientSessionManager.IsAuthenticated)
            return;

        try
        {
            await SaveFileAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                ex.Message,
                "Save Failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }


    private async Task SaveFileAsync()
    {
        if (_currentResult == null)
        {
            throw new InvalidOperationException(
                "There is no encrypted or decrypted file to save.");
        }

        if (string.IsNullOrWhiteSpace(
                _currentResult.OutputPath))
        {
            throw new InvalidOperationException(
                "The temporary output path is invalid.");
        }

        if (!File.Exists(
                _currentResult.OutputPath))
        {
            throw new FileNotFoundException(
                "The temporary output file no longer exists.",
                _currentResult.OutputPath);
        }

        var defaultName =
            string.IsNullOrWhiteSpace(
                FileVars.LoadedFile)
                ? "output"
                : Path.GetFileNameWithoutExtension(
                    FileVars.LoadedFile);

        var dialog =
            new SaveFileDialog
            {
                Filter =
                    "All Files (*.*)|*.*",

                RestoreDirectory =
                    true,

                AddExtension =
                    true,

                DefaultExt =
                    _currentResult.SuggestedExtension,

                FileName =
                    defaultName +
                    _currentResult.SuggestedExtension
            };

        if (dialog.ShowDialog() != true)
            return;

        if (string.IsNullOrWhiteSpace(
                dialog.FileName))
        {
            return;
        }

        ToggleButtons(
            false);

        try
        {
            await using var input =
                new FileStream(
                    _currentResult.OutputPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            await using var output =
                new FileStream(
                    dialog.FileName,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            await input.CopyToAsync(
                output);

            await output.FlushAsync();

            FileStatusLbl.Text =
                "File saved successfully.";

            FileStatusLbl.Foreground =
                Brushes.LimeGreen;

            MessageBox.Show(
                "The file has been saved successfully.",
                "Success",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        finally
        {
            ToggleButtons(
                true);
        }
    }


    // =========================================================
    // BUTTON STATE
    // =========================================================

    private void ToggleButtons(
        bool enabled)
    {
        OpenFileButton.IsEnabled =
            enabled;

        EncryptFileButton.IsEnabled =
            enabled;

        DecryptFileButton.IsEnabled =
            enabled;

        SaveFileButton.IsEnabled =
            enabled;
    }


    // =========================================================
    // FILE STATUS
    // =========================================================

    private void UpdateFileStatusLabel()
    {
        if (!FileVars.FileOpened)
        {
            FileStatusLbl.Text =
                "No file selected";

            return;
        }

        var fileName =
            Path.GetFileName(
                FileVars.LoadedFile);

        var fileSize =
            FormatFileSize(
                FileVars.FileSize);

        FileStatusLbl.Text =
            $"Opened file: {fileName}, Size: {fileSize}";
    }


    private static string FormatFileSize(
        long bytes)
    {
        string[] sizes =
        {
            "B",
            "KB",
            "MB",
            "GB",
            "TB"
        };

        double len =
            bytes;

        var order =
            0;

        while (len >= 1024 &&
               order < sizes.Length - 1)
        {
            order++;

            len /= 1024;
        }

        return
            $"{len:0.##} {sizes[order]}";
    }


    // =========================================================
    // CRYPTO STATUS
    // =========================================================

    private void StartCryptoStatus(
        string baseText)
    {
        _baseStatusText =
            baseText;

        _dotCount =
            0;

        _cryptoStatusTimer ??=
            new DispatcherTimer
            {
                Interval =
                    TimeSpan.FromMilliseconds(
                        500)
            };

        _cryptoStatusTimer.Tick -=
            CryptoStatusTick;

        _cryptoStatusTimer.Tick +=
            CryptoStatusTick;

        _cryptoStatusTimer.Start();
    }


    private void StopCryptoStatus()
    {
        _cryptoStatusTimer?.Stop();

        _dotCount =
            0;
    }


    private void CryptoStatusTick(
        object? sender,
        EventArgs e)
    {
        _dotCount =
            (_dotCount + 1) % 4;

        StatusLbl.Text =
            _baseStatusText +
            new string(
                '.',
                _dotCount);
    }
}


// =============================================================
// FILE STATE
// =============================================================

public static class FileVars
{
    public static string LoadedFile =
        string.Empty;

    public static string FileExtension =
        string.Empty;

    public static bool IsEncrypted;

    public static bool IsDecrypted;

    public static bool FileOpened { get; set; }

    public static long FileSize { get; set; }

    public static string? OriginalExtension { get; set; }
}