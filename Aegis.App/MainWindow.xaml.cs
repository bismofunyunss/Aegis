using Aegis.App.Interfaces;
using Aegis.App.Ipc;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Aegis.App
{
    public partial class MainWindow : Window
    {
        private readonly double _expandedWidth = 220;
        private readonly double _collapsedWidth = 60;

        private readonly Pages.LoginPage _loginPage;
        private readonly Pages.RegisterPage _registerPage;
        private readonly Pages.VaultPage _vaultPage;
        private readonly Pages.FileEncryptionPage _fileEncryptionPage;
        private readonly Pages.HashPage _hashPage;
        private readonly Pages.SettingsPage _settingsPage;

        public MainWindow()
        {
            InitializeComponent();

            MenuColumn.Width =
                new GridLength(_collapsedWidth);

            SetMenuTextVisibility(false);

            _loginPage =
                new Pages.LoginPage();

            _registerPage =
                new Pages.RegisterPage();

            _vaultPage =
                new Pages.VaultPage();

            _fileEncryptionPage =
                new Pages.FileEncryptionPage();

            _hashPage =
                new Pages.HashPage();

            _settingsPage =
                new Pages.SettingsPage();

            ContentFrame.Navigate(_loginPage);

            ResizeForPage(_loginPage);

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
                        _loginPage,

                    "Register" =>
                        _registerPage,

                    "Vault" =>
                        _vaultPage,

                    "FileEncryption" =>
                        _fileEncryptionPage,

                    "Hash" =>
                        _hashPage,

                    "Settings" =>
                        _settingsPage,

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
                new GridLength(_expandedWidth);

            SetMenuTextVisibility(true);

            Width +=
                _expandedWidth -
                _collapsedWidth;
        }


        private void MenuToggle_Checked(
            object sender,
            RoutedEventArgs e)
        {
            MenuColumn.Width =
                new GridLength(_collapsedWidth);

            SetMenuTextVisibility(false);

            Width -=
                _expandedWidth -
                _collapsedWidth;
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



