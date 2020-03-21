using System;
using System.Globalization;
using System.Security.Cryptography; // requires assembly reference: System.Security

namespace CryptLib
{
    /// <summary>
    /// Provides basic encryption/decryption for API tokens and any other sensitive information that needs to be persisted in plain text
    /// </summary>

    public class Crypto
    {
        /// <summary>
        /// Takes plain text string (e.g. "foo") and returns hex representation in a string of encrypted binary byte array (e.g. "0xa4520b") 
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>

        public static string Protect(string s)
        {
            try
            {
                byte[] Entropy = StrToByteArray(Globals.Copyright);
                byte[] Data = StrToByteArray(s);
                return ByteArrayToHexStr(ProtectedData.Protect(Data, Entropy, DataProtectionScope.LocalMachine));
            }
            catch
            {
            }
            return null;
        }

        /// <summary>
        /// Takes hex representation in a string of encrypted binary byte array (e.g. "0xa4520b") and returns it as a plain string (e.g. "foo")
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>

        public static string Unprotect(string s)
        {
            try
            {
                byte[] Entropy = StrToByteArray(Globals.Copyright);
                byte[] Data = HexStrToByteArray(s);
                return ByteArrayToStr(ProtectedData.Unprotect(Data, Entropy, DataProtectionScope.LocalMachine));
            }
            catch
            {
            }
            return null;
        }

        /// <summary>
        /// Converts a byte array to a string. Assumes the values in the byte array are ASCII characters, like: ['f', 'o', 'o']
        /// </summary>
        /// <param name="ba"></param>
        /// <returns></returns>

        private static string ByteArrayToStr(byte[] ba)
        {
            string s = "";
            foreach (byte b in ba)
            {
                s += (char)b;
            }
            return s;
        }

        /// <summary>
        /// Converts the passed string to a byte array by placing each char into a slot in the array assumes the input string is ASCII
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>

        private static byte[] StrToByteArray(string s)
        {
            byte[] b = new byte[s.Length];
            int i = 0;
            foreach (char c in s)
            {
                b[i++] = (byte)c;
            }
            return b;
        }

        /// <summary>
        /// Converts a byte array to a hex representation. E.g. [a3, 01, 9b] becomes "0xa3019b"
        /// </summary>
        /// <param name="ba"></param>
        /// <returns></returns>

        private static string ByteArrayToHexStr(byte[] ba)
        {
            string s = "0x";
            foreach (byte b in ba)
            {
                s += string.Format("{0:X2}", b);
            }
            return s;
        }

        /// <summary>
        /// Converts a hex representation of a byte array to a byte array. E.g. "0xa3019b" becomes [a3, 01, 9b]
        /// string must begin with "0x" and be an even length.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>

        private static byte[] HexStrToByteArray(string s)
        {
            byte[] b = null;
            if (s.Length > 2 && s.Length % 2 == 0 && s.Substring(0, 2).ToLower() == "0x")
            {
                b = new byte[s.Length / 2];
                for (int i = 0, j = 2; j < s.Length; j += 2)
                {
                    b[i++] = (byte)int.Parse(s.Substring(j, 2), NumberStyles.HexNumber);
                }
            }
            return b;
        }
    }
}
