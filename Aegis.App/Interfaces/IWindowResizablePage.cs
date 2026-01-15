using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.Interfaces
{
    public interface IWindowResizablePage
    {
        double DesiredWidth { get; }
        double DesiredHeight { get; }
    }
}
