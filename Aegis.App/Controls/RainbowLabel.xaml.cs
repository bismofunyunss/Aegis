using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Aegis.App.Controls
{
    public partial class RainbowLabel : UserControl
    {
        private TextBlock _textBlock;
        private CancellationTokenSource? _cts;

        public RainbowLabel()
        {
            _textBlock = new TextBlock
            {
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Colors.Black)
            };

            this.Content = _textBlock;
            this.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Call this after login to start flashing the username.
        /// </summary>
        public void ShowUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                StopRainbowAnimation();
                _textBlock.Text = "";
                this.Visibility = Visibility.Collapsed;
                return;
            }

            _textBlock.Text = $"Welcome, {username}";
            this.Visibility = Visibility.Visible;

            StartRainbowAnimation();
        }

        private void StartRainbowAnimation()
        {
            StopRainbowAnimation();

            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            Task.Run(async () =>
            {
                Random rnd = new();
                while (!token.IsCancellationRequested)
                {
                    Color randomColor = Color.FromRgb(
                        (byte)rnd.Next(0, 256),
                        (byte)rnd.Next(0, 256),
                        (byte)rnd.Next(0, 256));

                    await Dispatcher.BeginInvoke(() =>
                    {
                        _textBlock.Foreground = new SolidColorBrush(randomColor);
                    }, System.Windows.Threading.DispatcherPriority.Background);

                    await Task.Delay(200, token);
                }
            }, token);
        }

        private void StopRainbowAnimation()
        {
            if (_cts != null)
            {
                _cts.Cancel();
                _cts.Dispose();
                _cts = null;
            }
        }

        protected override void OnVisualParentChanged(DependencyObject oldParent)
        {
            base.OnVisualParentChanged(oldParent);
            if (this.Parent == null)
            {
                StopRainbowAnimation();
            }
        }
    }
}





