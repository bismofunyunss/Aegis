using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Aegis.App
{
    internal class FileLogger
    {
            private static readonly object LockObject = new();

            public static void Log(
                Exception ex,
                string context, string username)
            {
                try
                {
                    var folder =
                        Path.Combine(
                            Environment.GetFolderPath(
                                Environment.SpecialFolder.LocalApplicationData),
                            "Aegis",
                            "Users",
                            username);

                    Directory.CreateDirectory(folder);

                    var path =
                        Path.Combine(
                            folder,
                            "ExceptionLog.txt");

                    lock (LockObject)
                    {
                        using var writer =
                            new StreamWriter(
                                path,
                                append: true);

                        writer.WriteLine(
                            "====================================================");

                        writer.WriteLine(
                            $"UTC Time : {DateTime.UtcNow:O}");

                        writer.WriteLine(
                            $"Context  : {context}");

                        writer.WriteLine(
                            $"Type     : {ex.GetType().FullName}");

                        writer.WriteLine(
                            $"Message  : {ex.Message}");

                        writer.WriteLine();

                        writer.WriteLine(
                            ex.ToString());

                        writer.WriteLine();
                    }
                }
                catch
                {
                    //
                    // Never allow logging to crash encryption.
                    //
                }
            }
        }
    }
