using System;
using System.Collections.Generic;
using System.Security;
using System.Text;

namespace Aegis.App.Interfaces
{
    public interface IPasswordProvider
    {
        SecureString GetPassword();
    }
}
