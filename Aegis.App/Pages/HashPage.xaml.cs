using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Aegis.App.Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Aegis.App.Pages
{
    /// <summary>
    /// Interaction logic for HashPage.xaml
    /// </summary>
    public partial class HashPage : Page, IWindowResizablePage
    {
        
        public HashPage()
        {
            InitializeComponent();
        }

        public double DesiredWidth => 975; // width for this page
        public double DesiredHeight => 530; // height for this page
        private string selectedFilePath = null;

        private void OpenFileButton_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog()
            {
                Title = "Select File to Hash",
                Filter = "All Files (*.*)|*.*"
            };

            bool? result = openFileDialog.ShowDialog();

            if (result == true)
            {
                selectedFilePath = openFileDialog.FileName;
                // Optional: show file name somewhere (maybe in the button or a label)
                MessageBox.Show($"File selected:\n{selectedFilePath}", "File Selected", MessageBoxButton.OK, MessageBoxImage.Information);
            }
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

            string algorithm = selectedItem.Content.ToString();

            try
            {
                string hash = ComputeFileHash(selectedFilePath, algorithm);
                HashOutputTextBox.Text = hash;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error computing hash:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
                    return ComputeSha3Hash(filePath, 256);

                case "SHA3-384":
                    return ComputeSha3Hash(filePath, 384);

                case "SHA3-512":
                    return ComputeSha3Hash(filePath, 512);

                default:
                    throw new NotSupportedException($"Hash algorithm {algorithm} is not supported.");
            }
        }

        private string ComputeSha3Hash(string filePath, int bitSize)
            {
                IDigest digest = bitSize switch
                {
                    256 => new Sha3Digest(256),
                    384 => new Sha3Digest(384),
                    512 => new Sha3Digest(512),
                    _ => throw new ArgumentException("Invalid SHA3 bit size.")
                };

                byte[] buffer = new byte[8192];
                using (var stream = File.OpenRead(filePath))
                {
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        digest.BlockUpdate(buffer, 0, bytesRead);
                    }
                }

                byte[] result = new byte[digest.GetDigestSize()];
                digest.DoFinal(result, 0);
                return BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();
            }

    }
}
