using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace Aegis.App.Registration
{
    /// <summary>
    /// Interaction logic for RecoveryKey.xaml
    /// </summary>
    public partial class RecoveryKey : Window
    {
        public RecoveryKey(byte[] recoveryKey)
        {
            InitializeComponent();

            // Display the recovery key in hexadecimal
            RecoveryKeyBox.Text = Convert.ToHexString(recoveryKey);

            // Make window modal
            Owner = Application.Current.MainWindow;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;
        }

        private void Ok_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void Copy_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(RecoveryKeyBox.Text);
        }

        private void AcknowledgeCheckBox_Changed(object sender, RoutedEventArgs e)
        {
            // Enable OK button only if checkbox is checked
            OkButton.IsEnabled = AcknowledgeCheckBox.IsChecked == true;
        }

        protected override void OnClosed(EventArgs e)
        {
            // Clear sensitive UI memory
            RecoveryKeyBox.Text = string.Empty;
            Clipboard.Clear();
            AcknowledgeCheckBox.IsChecked = false;

            base.OnClosed(e);
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Prevent closing the window if acknowledgment not checked
            if (AcknowledgeCheckBox.IsChecked != true && DialogResult != true)
            {
                e.Cancel = true;
                MessageBox.Show(
                    "You must acknowledge that you have stored the recovery key safely before closing.",
                    "Warning",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
    }
}
