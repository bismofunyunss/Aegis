using Aegis.App.Crypto;
using Aegis.App.Global;
using Aegis.App.Helpers;
using Aegis.App.Interfaces;
using Microsoft.Win32;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using static Aegis.App.ParallelCtrEncryptor;
using Path = System.IO.Path;

namespace Aegis.App.Pages;

/// <summary>
///     Interaction logic for FileEncryptionPage.xaml
/// </summary>
public partial class FileEncryptionPage : Page, IWindowResizablePage
{
    private string _baseStatusText;
    private DispatcherTimer _cryptoStatusTimer;
    private int _dotCount;

    public FileEncryptionPage()
    {
        InitializeComponent();
    }

    public double DesiredWidth => 820; // width for this page
    public double DesiredHeight => 600; // height for this page


    private void OpenFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (Session.Session.GetUsername() == null)
            return;

        try
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "All Files (*.*)|*.*",
                Title = "Select a file to encrypt/decrypt.",
                CheckFileExists = true,
                CheckPathExists = true,
                RestoreDirectory = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            var result = openFileDialog.ShowDialog();
            if (result != true)
                return;

            var selectedFile = openFileDialog.FileName;
            var fileInfo = new FileInfo(selectedFile);
            if (fileInfo.Length == 0)
            {
                MessageBox.Show("The file is empty.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Open file stream
            var fileStream = File.Open(selectedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            FileVars.Result = fileStream;
            FileVars.FileOpened = true;
            FileVars.LoadedFile = selectedFile;
            FileVars.FileExtension = fileInfo.Extension.ToLower();
            FileVars.FileSize = fileInfo.Length;
            FileVars.IsEncrypted = false;
            FileVars.IsDecrypted = false;

            UpdateFileStatusLabel();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Error opening file: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            FileStatusLbl.Text = "Idle...";
            FileStatusLbl.Foreground = Brushes.WhiteSmoke;
        }
    }

    private async void EncryptFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (Session.Session.GetUsername() == null)
            return;

        if (FileVars.Result == null)
        {
            MessageBox.Show(
                "Please select a file before starting encryption.",
                "No File Selected",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        // Disable buttons
        OpenFileButton.IsEnabled = false;
        SaveFileButton.IsEnabled = false;
        EncryptFileButton.IsEnabled = false;
        DecryptFileButton.IsEnabled = false;

        // Initialize progress bar
        ProgressBar.Visibility = Visibility.Visible;
        ProgressBar.Minimum = 0;
        ProgressBar.Maximum = 100;
        ProgressBar.Value = 0;
        ProgressBar.Foreground = Brushes.DodgerBlue;

        // Show CryptoStatus label
        StartCryptoStatus("Encrypting");

        double currentValue = 0;
        double targetValue = 0;

        var progressTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(15)
        };

        progressTimer.Tick += (s, ev) =>
        {
            // Smooth interpolation
            var delta = (targetValue - currentValue) * 0.1;
            if (Math.Abs(delta) < 0.2)
            {
                currentValue = targetValue;
                ProgressBar.Value = currentValue;
                if (currentValue >= 100)
                    progressTimer.Stop();
            }
            else
            {
                currentValue += delta;
                ProgressBar.Value = currentValue;
            }
        };

        var uiProgress = new Progress<double>(percent =>
        {
            targetValue = Math.Clamp(percent, 0, 100);
            if (!progressTimer.IsEnabled) progressTimer.Start();
        });

        var success = false;

        try
        {
            UpdateFileStatusLabel();

            MessageBox.Show(
                "Do NOT close the program while encrypting. Corrupted data may occur.",
                "Warning",
                MessageBoxButton.OK,
                MessageBoxImage.Exclamation);

            // Perform the encryption
            success = await PerformEncryptionAsync(uiProgress);

            if (success)
            {
                // Ensure progress reaches 100%
                targetValue = 100;
                while (ProgressBar.Value < 100)
                    await Task.Delay(50);

                FileStatusLbl.Text = "File encrypted.";
                FileStatusLbl.Foreground = Brushes.LimeGreen;

                MessageBox.Show(
                    "File was encrypted successfully. You may now export it.",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                FileVars.IsEncrypted = true;
                FileVars.IsDecrypted = false;
            }
        }
        catch (FileNotFoundException)
        {
            FileVars.IsEncrypted = false;
            MessageBox.Show("File not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (CryptographicException)
        {
            FileVars.IsEncrypted = false;
            MessageBox.Show("Encryption failed due to cryptographic error.", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            FileVars.IsEncrypted = false;
            MessageBox.Show($"Unexpected error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            progressTimer.Stop();
            StopCryptoStatus();

            // Re-enable buttons
            OpenFileButton.IsEnabled = true;
            SaveFileButton.IsEnabled = true;
            EncryptFileButton.IsEnabled = true;
            DecryptFileButton.IsEnabled = true;

            if (!success)
            {
                FileStatusLbl.Text = "File encryption failed.";
                FileStatusLbl.Foreground = Brushes.Red;
            }
            else
            {
                FileStatusLbl.Text = "File ready to be saved.";
                FileStatusLbl.Foreground = Brushes.White;
            }
        }
    }


    private async void DecryptFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (Session.Session.GetUsername() == null)
            return;

        if (FileVars.Result == null)
        {
            MessageBox.Show(
                "Please select an encrypted file before decrypting.",
                "No File Selected",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        StartCryptoStatus("Decrypting");

        DecryptFileButton.IsEnabled = false;
        EncryptFileButton.IsEnabled = false;
        OpenFileButton.IsEnabled = false;
        SaveFileButton.IsEnabled = false;

        // --- Progress bar setup ---
        ProgressBar.Visibility = Visibility.Visible;
        ProgressBar.Minimum = 0;
        ProgressBar.Maximum = 100;
        ProgressBar.Value = 0;

        double currentValue = 0;
        double targetValue = 0;

        var progressTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(15)
        };

        progressTimer.Tick += (_, __) =>
        {
            var delta = (targetValue - currentValue) * 0.1;

            if (Math.Abs(delta) < 0.2)
            {
                currentValue = targetValue;
                ProgressBar.Value = currentValue;
                progressTimer.Stop();
            }
            else
            {
                currentValue += delta;
                ProgressBar.Value = currentValue;
            }
        };

        var uiProgress = new Progress<double>(percent =>
        {
            targetValue = Math.Clamp(percent, 0, 100);
            if (!progressTimer.IsEnabled)
                progressTimer.Start();
        });

        try
        {
            MessageBox.Show(
                "Do NOT close the program while decrypting. This may cause irreversible data loss.",
                "Warning",
                MessageBoxButton.OK,
                MessageBoxImage.Exclamation);

            var success = await PerformDecryptionAsync(uiProgress);

            if (success)
            {
                await Task.Delay(1200); // allow 100% animation to finish

                FileStatusLbl.Text = "File decrypted.";
                FileStatusLbl.Foreground = Brushes.LimeGreen;

                MessageBox.Show(
                    "File was decrypted successfully.",
                    "Success",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                UpdateFileStatusLabel();
                ProgressBar.Value = 0;

                FileVars.IsEncrypted = false;
                FileVars.IsDecrypted = true;
            }
        }
        catch (CryptographicException)
        {
            MessageBox.Show(
                "Decryption failed. The file may be corrupted or the key is invalid.",
                "Decryption Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            FileVars.IsEncrypted = true;
            FileVars.IsDecrypted = false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Unexpected error:\n{ex.Message}",
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            FileVars.IsEncrypted = true;
            FileVars.IsDecrypted = false;
        }
        finally
        {
            progressTimer.Stop();
            DecryptFileButton.IsEnabled = true;
            EncryptFileButton.IsEnabled = true;
            OpenFileButton.IsEnabled = true;
            SaveFileButton.IsEnabled = true;
            StopCryptoStatus();
            FileStatusLbl.Text = "File ready to be saved.";
            FileStatusLbl.Foreground = Brushes.White;
        }
    }


    private async void SaveFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (Session.Session.GetUsername() == null)
            return;

        try
        {
            var saveFileDialog = new SaveFileDialog
            {
                FilterIndex = 1,
                ShowHiddenItems = true,
                CheckFileExists = false,
                CheckPathExists = false,
                RestoreDirectory = true,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
            };

            // Determine extension and filter
            string extension;
            string filter;
            if (FileVars.IsEncrypted)
            {
                extension = ".encrypted";
                filter = "Encrypted files (*.encrypted)|*.encrypted";
            }
            else
            {
                extension = string.IsNullOrEmpty(FileVars.OriginalExtension) ? ".dat" : FileVars.OriginalExtension;
                filter = string.IsNullOrEmpty(FileVars.OriginalExtension)
                    ? "All Files (*.*)|*.*"
                    : $"{extension.TrimStart('.').ToUpper()} files (*{extension})|*{extension}|All Files (*.*)|*.*";
            }

            saveFileDialog.Filter = filter;
            saveFileDialog.DefaultExt = extension;

            // ShowDialog() returns nullable bool
            var result = saveFileDialog.ShowDialog();

            if (result != true)
                // User cancelled
                return;

            var selectedFileName = saveFileDialog.FileName;
            if (string.IsNullOrEmpty(Path.GetExtension(selectedFileName)) ||
                !selectedFileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                selectedFileName = Path.ChangeExtension(selectedFileName, extension);

            // Reset stream position before writing
            FileVars.Result.Position = 0;

            await FileIO.WriteFileStreamAsync(selectedFileName, FileVars.Result);

            // Erase original only, not the saved file
            if (!string.IsNullOrEmpty(FileVars.LoadedFile) && File.Exists(FileVars.LoadedFile))
                await SecureFileEraser.SecurelyEraseFileAsync(FileVars.LoadedFile,
                    SecureFileEraser.IsSSD(FileVars.LoadedFile));


            FileStatusLbl.Text = "File saved successfully.";
            FileStatusLbl.Foreground = Brushes.LimeGreen;
            MessageBox.Show("File saved successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);

            // Cleanup
            FileVars.Result.Dispose();
            FileVars.Result = null;
            FileVars.FileOpened = false;
            FileVars.FileSize = 0;
            FileVars.IsEncrypted = false;
            FileVars.IsDecrypted = false;
        }
        catch (Exception ex)
        {
            MessageBox.Show("An unexpected error occurred while saving the file.", "Error", MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void UpdateFileStatusLabel()
    {
        // Only default if LoadedFile was never set
        if (FileVars.LoadedFile == null)
        {
            FileStatusLbl.Text = "No file selected";
            FileStatusLbl.ToolTip = null;
            return;
        }

        // Show the file name and size even if the file has been deleted
        var fileName = Path.GetFileName(FileVars.LoadedFile);
        var fileSize = FormatFileSize(FileVars.FileSize); // You can store original size before deletion

        FileStatusLbl.Foreground = Brushes.White;
        FileStatusLbl.Text = $"Opened file: {fileName}, File size: {fileSize}";

        FileStatusLbl.ToolTip = $"File name: {fileName}, File size: {fileSize}";



    // File is loaded (even if Result is null after encryption/decryption)
     fileName = Path.GetFileName(FileVars.LoadedFile);
         fileSize = FormatFileSize(FileVars.FileSize); // Make sure FileVars.FileSize is updated correctly

        FileStatusLbl.Foreground = Brushes.White;
        FileStatusLbl.Text = $"Opened file: {fileName}, File size: {fileSize}";

        FileStatusLbl.ToolTip = $"File name: {fileName}, File size: {fileSize}";
    }


    public static string FormatFileSize(long bytes)
    {
        string[] sizes = { "bytes", "KB", "MB", "GB", "TB", "PB" };
        double len = bytes;
        var order = 0;

        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return $"{len:0.##} {sizes[order]}";
    }

    private async Task<bool> PerformEncryptionAsync(IProgress<double> progress)
    {
        if (!FileVars.FileOpened)
            throw new InvalidOperationException("No file is opened. Please open a file before encrypting.");

        if (string.IsNullOrEmpty(FileVars.LoadedFile))
            throw new FileNotFoundException("No file is selected or the file path is empty.");

        if (FileVars.IsEncrypted)
            throw new InvalidOperationException("File is already encrypted. Please decrypt or export it first.");

        var inputStream = FileVars.Result ?? throw new InvalidOperationException("No input stream.");
        inputStream.Position = 0;

        // ---- Peek header to prevent double encryption ----
        if (inputStream.Length >= FileVars.FileSignature.Length)
        {
            var header = new byte[FileVars.FileSignature.Length];
            var bytesRead = await inputStream.ReadAsync(header, 0, header.Length);

            if (bytesRead != header.Length)
                throw new IOException("Failed to read the full file header.");

            if (header.SequenceEqual(FileVars.FileSignature))
                throw new InvalidOperationException("File is already encrypted.");

            inputStream.Position = 0;
        }

        var crypto = Session.Session.GetCryptoSession();
        if (crypto == null || !crypto.IsMasterKeyInitialized)
            throw new SecurityException("Crypto session not initialized.");


        var fileKeySalt = RandomNumberGenerator.GetBytes(128);
        using var fileKey = new FileKey(
            crypto.MasterKey,
            fileKeySalt,
            "File-Encryption-Key"u8,
            64); var salts = CryptoMethods.SaltGenerator.CreateSalts(128);
        var Keys = KeyDerivation.DeriveKeys(fileKey, salts);

        try
        {
            // ---- Final output stream ----
            var finalTempPath = Path.GetTempFileName();
            var finalStream = new FileStream(
                finalTempPath,
                FileMode.Create,
                FileAccess.ReadWrite,
                FileShare.None,
                4096
            );

            // ---- Write file header ----
            var ext = Path.GetExtension(FileVars.LoadedFile) ?? string.Empty;
            var extBytes = Encoding.UTF8.GetBytes(ext);

            if (extBytes.Length > 255)
                throw new InvalidOperationException("Extension too long.");

            // File header layout:
            // [FileSignature][FileKeySalt][CryptoSalts(8*128)][ExtensionLength(1)][Extension(n)]
            await finalStream.WriteAsync(FileVars.FileSignature);
            await finalStream.WriteAsync(fileKeySalt);

            // Write all 8 crypto salts
            for (var i = 0; i < salts.Length; i++)
                await finalStream.WriteAsync(salts[i]);

            // Write extension
            await finalStream.WriteAsync(new[] { (byte)extBytes.Length });
            await finalStream.WriteAsync(extBytes);

            // ---- Encrypt payload ----
            var tempEncryptedPath = Path.GetTempFileName();

            await using (var tempEncryptedStream = new FileStream(
                             tempEncryptedPath,
                             FileMode.Create,
                             FileAccess.ReadWrite,
                             FileShare.None,
                             4096,
                             FileOptions.DeleteOnClose))
            {
                await SecureParallelEncryptor.EncryptV3(
                    inputStream,
                    tempEncryptedStream,
                    Keys,
                    progress
                );

                tempEncryptedStream.Position = 0;
                await tempEncryptedStream.CopyToAsync(finalStream);
            }

            // ---- Finalize ----
            await finalStream.FlushAsync();
            finalStream.Position = 0;

            // Replace global stream
            FileVars.Result?.Dispose();
            FileVars.Result = finalStream;
            FileVars.IsEncrypted = true;
            FileVars.IsDecrypted = false;

            UpdateFileStatusLabel();

            return true;
        }

        finally
        {
            MemoryHandling.Clear(fileKeySalt);
            fileKey.Dispose();
            foreach (var salt in salts)
                MemoryHandling.Clear(salt);
            Keys?.Dispose();
        }
    }

    private static async Task<bool> PerformDecryptionAsync(IProgress<double> progress)
    {
        if (!FileVars.FileOpened)
            throw new InvalidOperationException("No file opened.");

        if (FileVars.Result == null)
            throw new InvalidOperationException("No input stream.");

        var input = FileVars.Result;
        input.Position = 0;

        // ---- 1. Read and verify file signature ----
        var sig = await HelperMethods.ReadExactAsync(input, FileVars.FileSignature.Length);
        if (!sig.SequenceEqual(FileVars.FileSignature))
            throw new CryptographicException("Invalid file signature.");

        // ---- 2. Read FileKeySalt ----
        var fileKeySalt = await HelperMethods.ReadExactAsync(input, 128);

        // ---- 3. Re-derive file key ----
        var crypto = Session.Session.GetCryptoSession();
        if (crypto == null || !crypto.IsMasterKeyInitialized)
            throw new SecurityException("Crypto session not initialized.");

        // Create a FileKey from the master key and the stored salt
        using var fileKey = new FileKey(
            crypto.MasterKey,
            fileKeySalt,                         // salt read from file
            "File-Encryption-Key"u8.ToArray(),  // info
            64                                   // desired length
        );

        // ---- 4. Read 8 crypto salts ----
        var cryptoSalts = new byte[8][];
        for (var i = 0; i < 8; i++)
            cryptoSalts[i] = await HelperMethods.ReadExactAsync(input, 128);

        // ---- 5. Derive all keys for decryption ----
        var Keys = KeyDerivation.DeriveKeys(fileKey, cryptoSalts);

        // ---- 5. Read extension ----
        var extLen = input.ReadByte();
        var extBytes = await HelperMethods.ReadExactAsync(input, extLen);
        var originalExtension = Encoding.UTF8.GetString(extBytes);

        // ---- 6. Encrypted payload starts here ----
        var payloadStart = input.Position;
        var payloadLength = input.Length - payloadStart; // full remaining stream is payload

        // ---- 8. Prepare output stream ----
        var tempOutPath = Path.GetTempFileName();
        await using var output = new FileStream(
            tempOutPath,
            FileMode.Create,
            FileAccess.ReadWrite,
            FileShare.None,
            4096
        );

        // ---- 9. Decrypt payload ----
        await SecureParallelEncryptor.DecryptV3(
            input,
            output,
            Keys,
            progress
        );

        output.Position = 0;

        // ---- 10. Replace global stream ----
        FileVars.Result?.Dispose();
        FileVars.Result = output;
        FileVars.Result.Position = 0;
        FileVars.IsEncrypted = false;
        FileVars.IsDecrypted = true;
        FileVars.OriginalExtension = originalExtension;

        // ---- 11. Clear sensitive buffers ----
        MemoryHandling.Clear(fileKeySalt);
        fileKey.Dispose();
        foreach (var salt in cryptoSalts)
            MemoryHandling.Clear(salt);
        Keys?.Dispose();

        return true;
    }

    private void StartCryptoStatus(string baseText)
    {
        _baseStatusText = baseText;
        _dotCount = 0;

        FileStatusLbl.Text = baseText;
        FileStatusLbl.Visibility = Visibility.Visible;

        _cryptoStatusTimer ??= new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500)
        };

        _cryptoStatusTimer.Tick -= CryptoStatusTick;
        _cryptoStatusTimer.Tick += CryptoStatusTick;
        _cryptoStatusTimer.Start();
    }

    private void StopCryptoStatus()
    {
        _cryptoStatusTimer?.Stop();
        FileStatusLbl.Visibility = Visibility.Collapsed;
    }

    private void CryptoStatusTick(object? sender, EventArgs e)
    {
        _dotCount = (_dotCount + 1) % 4; // 0..3 dots
        FileStatusLbl.Text = _baseStatusText + new string('.', _dotCount);
    }


    // Static class to track file state
    public static class FileVars
    {
        public static string LoadedFile = string.Empty;
        public static Stream? Result;
        public static string FileExtension = string.Empty;
        public static bool IsEncrypted;
        public static bool IsDecrypted;
        public static readonly byte[] FileSignature = "v1.0"u8.ToArray();
        public static bool FileOpened { get; set; }
        public static long FileSize { get; set; }
        public static string? OriginalExtension { get; set; }
    }
}