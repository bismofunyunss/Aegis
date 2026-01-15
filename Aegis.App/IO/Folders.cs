using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aegis.App.IO
{
    internal class Folders
    {
        public static string GetLocalAppDataFolder()
        {
            return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        public static string CreateDirectory(string location, string folderName)
        {
            if (string.IsNullOrWhiteSpace(location))
                throw new ArgumentException("Location cannot be null or empty.", nameof(location));

            if (string.IsNullOrWhiteSpace(folderName))
                throw new ArgumentException("Folder name cannot be null or empty.", nameof(folderName));

            string fullPath = Path.Combine(location, folderName);

            // Create the directory if it doesn't exist
            if (!Directory.Exists(fullPath))
            {
                Directory.CreateDirectory(fullPath);
            }

            return fullPath;
        }

        public static string GetUserFolder(string userName)
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Aegis",
                "Users",
                userName);
        }

        /// <summary>
        /// Returns the path to the user's folder under AppData\Local\Aegis\Users\{userName}.
        /// Creates the folder if it does not exist.
        /// </summary>
        public static string GetOrCreateUserFolder(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentException("Invalid username", nameof(userName));

            // Base folder: %LOCALAPPDATA%\Aegis\Users
            string baseFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Aegis",
                "Users"
            );

            // Ensure base folder exists
            Directory.CreateDirectory(baseFolder);

            // User-specific folder
            string userFolder = Path.Combine(baseFolder, userName);

            // Ensure user folder exists
            Directory.CreateDirectory(userFolder);

            return userFolder;
        }
    }


}

