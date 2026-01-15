using Aegis.App.Interfaces;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Aegis.App
{
    public partial class MainWindow : Window
    {
        private double ExpandedWidth = 220;
        private double CollapsedWidth = 60;

        private Pages.LoginPage loginPage;
        private Pages.RegisterPage registerPage;
        private Pages.VaultPage vaultPage;
        private Pages.FileEncryptionPage fileEncryptionPage;
        private Pages.HashPage hashPage;
        private Pages.SettingsPage settingsPage;

        public MainWindow()
        {
            InitializeComponent();

            // Collapsed by default
            MenuColumn.Width = new GridLength(CollapsedWidth);
            SetMenuTextVisibility(false);

            // Create pages once
            loginPage = new Pages.LoginPage();
            registerPage = new Pages.RegisterPage();
            vaultPage = new Pages.VaultPage();
            fileEncryptionPage = new Pages.FileEncryptionPage();
            hashPage = new Pages.HashPage();
            settingsPage = new Pages.SettingsPage();

            // Navigate to default page
            ContentFrame.Navigate(loginPage);
            MenuList.SelectedIndex = 0;
        }

        private void MenuList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (MenuList.SelectedItem is ListBoxItem item)
            {
                Page page = item.Tag.ToString() switch
                {
                    "Login" => loginPage,
                    "Register" => registerPage,
                    "Vault" => vaultPage,
                    "FileEncryption" => fileEncryptionPage,
                    "Hash" => hashPage,
                    "Settings" => settingsPage,
                    _ => null
                };

                if (page != null)
                {
                    ContentFrame.Navigate(page);

                    // Resize window if the page implements IWindowResizablePage
                    if (page is IWindowResizablePage resizable)
                    {
                        this.Width = resizable.DesiredWidth;
                        this.Height = resizable.DesiredHeight;
                    }
                    else
                    {
                        this.Width = 900;
                        this.Height = 600;
                    }
                }
            }
        }


        private void MenuToggle_Checked(object sender, RoutedEventArgs e)
        {
            MenuColumn.Width = new GridLength(CollapsedWidth);
            SetMenuTextVisibility(false);
        }

        private void MenuToggle_Unchecked(object sender, RoutedEventArgs e)
        {
            MenuColumn.Width = new GridLength(ExpandedWidth);
            SetMenuTextVisibility(true);
        }

        private void SetMenuTextVisibility(bool visible)
        {
            if (MenuList == null) return;

            foreach (var item in MenuList.Items)
            {
                if (item is ListBoxItem listItem && listItem.Content is StackPanel sp)
                {
                    if (sp.Children.Count > 1 && sp.Children[1] is TextBlock tb)
                    {
                        tb.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
                    }
                }
            }
        }

        // Top bar dragging
        private void TopBar_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                this.DragMove();
        }

        // Window buttons
        private void Minimize_Click(object sender, RoutedEventArgs e) => this.WindowState = WindowState.Minimized;

        private void Maximize_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = this.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }

        private void Close_Click(object sender, RoutedEventArgs e) => this.Close();
    }
}



