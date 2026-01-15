using System;
using System.Globalization;
using System.Net;
using System.Security;
using System.Windows.Data;

namespace Aegis.App.Converters
{
    public sealed class SecureStringToStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is SecureString ss)
                return new NetworkCredential(string.Empty, ss).Password;

            return string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}

