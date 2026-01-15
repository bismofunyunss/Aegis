using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Threading;
using Aegis.App.Pages;

namespace Aegis.App.Helpers
{
    public class Dispatcher : UserControl
    {
        public void SafeInvoke(FileEncryptionPage fileEncryptionPage, Action action)
        {
            // 'this' is your Window
            if (this.Dispatcher.CheckAccess())
                action();
            else
                this.Dispatcher.Invoke(action);
        }
        public async Task SafeInvokeAsync(Action action)
        {
            if (this.Dispatcher.CheckAccess())
                action();
            else
                await this.Dispatcher.InvokeAsync(action);
        }
    }
}
