using Aegis.App.Ipc;
using Aegis.Contracts;
using Aegis.Contracts.IPC;
using System;
using System.IO;
using System.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Windows;

namespace Aegis.Client.Services;

public static class IpcErrorHandler
{
    public static void Show(
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if (exception is IpcException ipcException)
        {
            Show(ipcException.ErrorCode);
            return;
        }

        if (exception is OperationCanceledException)
        {
            Show(IpcErrorCode.Cancelled);
            return;
        }

        if (exception is SecurityException)
        {
            Show(IpcErrorCode.SecurityFailure);
            return;
        }

        if (exception is CryptographicException)
        {
            Show(IpcErrorCode.CryptographicFailure);
            return;
        }

        if (exception is FileNotFoundException)
        {
            Show(IpcErrorCode.FileNotFound);
            return;
        }

        if (exception is IOException)
        {
            Show(IpcErrorCode.FileFailure);
            return;
        }

        if (exception is ArgumentException)
        {
            Show(IpcErrorCode.ValidationFailure);
            return;
        }

        Show(IpcErrorCode.InternalFailure);
    }

    public static void Show(
        IpcErrorCode errorCode)
    {
        string message =
            IpcErrorMessages.Get(errorCode);

        (
            string title,
            MessageBoxImage image) =
            errorCode switch
            {
                IpcErrorCode.FileAlreadyEncrypted =>
                    (
                        "File Already Encrypted",
                        MessageBoxImage.Information
                    ),

                IpcErrorCode.FileNotEncrypted =>
                    (
                        "File Not Encrypted",
                        MessageBoxImage.Information
                    ),

                IpcErrorCode.FileNotFound =>
                    (
                        "File Not Found",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.InvalidFileFormat =>
                    (
                        "Invalid File Format",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.UnsupportedFileVersion =>
                    (
                        "Unsupported File Version",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.FileIntegrityFailure =>
                    (
                        "File Integrity Check Failed",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.SessionExpired =>
                    (
                        "Session Expired",
                        MessageBoxImage.Warning
                    ),

                IpcErrorCode.Cancelled =>
                    (
                        "Operation Cancelled",
                        MessageBoxImage.Information
                    ),

                IpcErrorCode.AuthenticationFailed =>
                    (
                        "Authentication Failed",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.AuthorizationFailed =>
                    (
                        "Authorization Failed",
                        MessageBoxImage.Warning
                    ),

                IpcErrorCode.ValidationFailure =>
                    (
                        "Invalid Request",
                        MessageBoxImage.Warning
                    ),

                IpcErrorCode.SecurityFailure =>
                    (
                        "Security Error",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.CryptographicFailure =>
                    (
                        "Cryptographic Error",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.FileFailure =>
                    (
                        "File Error",
                        MessageBoxImage.Error
                    ),

                IpcErrorCode.InternalFailure =>
                    (
                        "Operation Failed",
                        MessageBoxImage.Error
                    ),

                _ =>
                    (
                        "Operation Failed",
                        MessageBoxImage.Error
                    )
            };

        MessageBox.Show(
            message,
            title,
            MessageBoxButton.OK,
            image);
    }
}
