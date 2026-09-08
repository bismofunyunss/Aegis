using Aegis.Contracts;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.App.Ipc;

public sealed class IpcException : Exception
{
    public IpcErrorCode ErrorCode { get; }

    public IpcException(
        IpcErrorCode errorCode,
        string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public IpcException(
        IpcErrorCode errorCode,
        string message,
        Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}
