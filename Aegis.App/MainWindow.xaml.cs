using Aegis.App.Interfaces;
using Aegis.App.Ipc;
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

            MenuColumn.Width =
                new GridLength(CollapsedWidth);

            SetMenuTextVisibility(false);

            loginPage =
                new Pages.LoginPage();

            registerPage =
                new Pages.RegisterPage();

            vaultPage =
                new Pages.VaultPage();

            fileEncryptionPage =
                new Pages.FileEncryptionPage();

            hashPage =
                new Pages.HashPage();

            settingsPage =
                new Pages.SettingsPage();

            ContentFrame.Navigate(loginPage);

            ResizeForPage(loginPage);

            MenuList.SelectedIndex = 0;
        }

        private void MenuList_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            if (MenuList.SelectedItem is not ListBoxItem item)
                return;


            Page? page =
                item.Tag?.ToString() switch
                {
                    "Login" =>
                        loginPage,

                    "Register" =>
                        registerPage,

                    "Vault" =>
                        vaultPage,

                    "FileEncryption" =>
                        fileEncryptionPage,

                    "Hash" =>
                        hashPage,

                    "Settings" =>
                        settingsPage,

                    _ =>
                        null
                };


            if (page == null)
                return;


            ContentFrame.Navigate(page);

            ResizeForPage(page);
        }

        private void ResizeForPage(Page page)
        {
            if (page is IWindowResizablePage resizable)
            {
                Width = resizable.DesiredWidth;
                Height = resizable.DesiredHeight;
            }
        }

        private void MenuToggle_Unchecked(
            object sender,
            RoutedEventArgs e)
        {
            MenuColumn.Width =
                new GridLength(ExpandedWidth);

            SetMenuTextVisibility(true);

            Width +=
                ExpandedWidth -
                CollapsedWidth;
        }


        private void MenuToggle_Checked(
            object sender,
            RoutedEventArgs e)
        {
            MenuColumn.Width =
                new GridLength(CollapsedWidth);

            SetMenuTextVisibility(false);

            Width -=
                ExpandedWidth -
                CollapsedWidth;
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

    public interface IWindowResizablePage
    {
        double DesiredWidth { get; }
        double DesiredHeight { get; }
    }
}



