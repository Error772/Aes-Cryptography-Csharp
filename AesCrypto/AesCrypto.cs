using System;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.IO;

namespace AesCrypto
{
    public static class AesManager
    {
        //=================================[Notes]================================\\

        // Dev => { T.me/Ali_Cod7 }
        //
        // Return Encrypted Strings With CBC | ECB Mode { Custom Paddings And Keysizes }
        //
        // 2 Modes Are Avalible For CBC Method :
        //
        // 1- With Specified IV [By User]
        // 2- Random IV [Generates Random IV]
        //
        // *Note => For ECB Mode Leave IV Filed Blank (Or You Can Fill It. Doesn't Make Change...)
        // *Note => *Note => An Encrypted CBC String With Random Initialization Vector Can Not Be Decrypted!
        //  
        // 128-Bit | Secret Key Length -> 16 { IV Length For CBC -> 16 }
        // 192-Bit | Secret Key Length -> 24 { IV Length For CBC -> 16 }
        // 256-Bit | Secret Key Length -> 32 { IV Length For CBC -> 16 }
        //
        // PKCS7 , ANSIX923 , Zeros => Stable Result
        // SO10126 => Variable Result

        //=================================[Codes]================================\\

        public static string Encrypt(string Plaintext, string Secret, string IV = null, Ctype Cipher = Ctype.ECB, KeySize Size = KeySize.Bit128, Ptype Padding = Ptype.PKCS7)
        {
            string Er = Error(true, Cipher, Secret, IV, Size);
            if (Er != null)
            {
                return Er;
            }
            try
            {
                string Output = null;
                byte[] Data = Encoding.UTF8.GetBytes(Plaintext);
                byte[] Key = Encoding.ASCII.GetBytes(Secret).Take(32).ToArray();
                byte[] Ps = null;

                Cipher = (Ctype)(CipherMode)Cipher;

                if (Cipher == Ctype.CBC)
                {
                    if (IV != null)
                    {
                        Ps = Encoding.UTF8.GetBytes(IV).Take(16).ToArray();
                    }
                }

                RijndaelManaged RiM = new RijndaelManaged();
                RiM.Key = Key;
                RiM.Mode = (CipherMode)Cipher;
                RiM.KeySize = (int)Size;
                RiM.BlockSize = 128;
                RiM.Padding = (PaddingMode)Padding;
                if (Cipher == Ctype.CBC)
                {
                    if (IV == null)
                    {
                        RiM.GenerateIV();
                    }
                    else
                    {
                        RiM.IV = Ps;
                    }
                }

                try
                {
                    MemoryStream Ms = new MemoryStream();

                    if (Cipher == Ctype.CBC)
                    {
                        if (IV == null)
                        {
                            using (CryptoStream Cs = new CryptoStream(Ms, RiM.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                StreamWriter Sw = new StreamWriter(Cs);
                                Sw.Write(Plaintext);
                                Sw.Close();
                                Cs.Close();
                            }
                        }
                        else
                        {
                            using (CryptoStream Cs = new CryptoStream(Ms, RiM.CreateEncryptor(Key, Ps), CryptoStreamMode.Write))
                            {
                                StreamWriter Sw = new StreamWriter(Cs);
                                Sw.Write(Plaintext);
                                Sw.Close();
                                Cs.Close();
                            }
                        }
                    }
                    else
                    {
                        using (CryptoStream Cs = new CryptoStream(Ms, RiM.CreateEncryptor(Key, null), CryptoStreamMode.Write))
                        {
                            StreamWriter Sw = new StreamWriter(Cs);
                            Sw.Write(Plaintext);
                            Sw.Close();
                            Cs.Close();
                        }
                    }
                    byte[] Encoded = Ms.ToArray();
                    Output = Convert.ToBase64String(Encoded);

                    Ms.Close();
                }
                finally
                {
                    RiM.Clear();
                }
                return Output;
            }
            catch { return Er; }
        }

        public static string Decrypt(string EncryptedText, string Secret, string IV = null, Ctype Cipher = Ctype.ECB, KeySize Size = KeySize.Bit128, Ptype Padding = Ptype.PKCS7)
        {
            string Er = Error(false, Cipher, Secret, IV, Size);
            if (Er != null)
            {
                return Er;
            }
            try
            {
                byte[] Key = Encoding.UTF8.GetBytes(Secret);

                RijndaelManaged RiM = new RijndaelManaged();
                RiM.Key = Key;
                RiM.Mode = (CipherMode)Cipher;
                RiM.Padding = (PaddingMode)Padding;
                RiM.KeySize = (int)Size;
                RiM.BlockSize = 128;

                CryptoStream Cs;
                MemoryStream Ms = new MemoryStream(Convert.FromBase64String(EncryptedText));
                if (IV != null)
                {
                    byte[] Ps = Encoding.UTF8.GetBytes(IV);
                    RiM.IV = Ps;
                    Cs = new CryptoStream(Ms, RiM.CreateDecryptor(Key, Ps), CryptoStreamMode.Read);
                }
                else
                {
                    Cs = new CryptoStream(Ms, RiM.CreateDecryptor(Key, null), CryptoStreamMode.Read);
                }
                return new StreamReader(Cs).ReadToEnd();
            }
            catch { return "Invalid Parameters!"; }
        }

        public enum Ctype { CBC = 1 , ECB = 2 }

        public enum KeySize { Bit128 = 128 , Bit192 = 192 , Bit256 = 256 }

        public enum Ptype { ANSIX923 = 4 , ISO10126 = 5 , PKCS7 = 2 , Zeros = 3 }

        private static string Error(bool Mode, Ctype Cipher, string Secret, string IV, KeySize Size)
        {
            string Error = null;
            bool Empty = string.IsNullOrEmpty(IV);
            try
            {
                switch (Cipher)
                {
                    case Ctype.CBC:
                        switch (Mode)
                        {
                            case true:
                                bool Len = IV.Length == 16;
                                switch (Len)
                                {
                                    case true:
                                        if (Size == KeySize.Bit128 && Secret.Length != 16)
                                        {
                                            Error = "Length of secret key should be 16 for 128 bits key size!";
                                        }
                                        else if (Size == KeySize.Bit192 && Secret.Length != 24)
                                        {
                                            Error = "Length of secret key should be 24 for 192 bits key size!";
                                        }
                                        else if (Size == KeySize.Bit256 && Secret.Length != 32)
                                        {
                                            Error = "Length of secret key should be 32 for 256 bits key size!";
                                        }
                                        break;
                                    case false:
                                        Error = "Length of IV must be 16!";
                                        break;
                                }
                                break;
                            case false:
                                switch (Empty)
                                {
                                    case false:
                                        switch (IV.Length)
                                        {
                                            case 16:
                                                if (Size == KeySize.Bit128 && Secret.Length != 16)
                                                {
                                                    Error = "Length of secret key should be 16 for 128 bits key size!";
                                                }
                                                else if (Size == KeySize.Bit192 && Secret.Length != 24)
                                                {
                                                    Error = "Length of secret key should be 24 for 192 bits key size!";
                                                }
                                                else if (Size == KeySize.Bit256 && Secret.Length != 32)
                                                {
                                                    Error = "Length of secret key should be 32 for 256 bits key size!";
                                                }
                                                break;
                                            default:
                                                Error = "Length of IV must be 16!";
                                                break;
                                        }
                                        break;
                                    default:
                                        Error = "IV can not be null!";
                                        break;
                                }
                                break;
                        }
                        break;
                    case Ctype.ECB:
                        if (Size == KeySize.Bit128 && Secret.Length != 16)
                        {
                            Error = "Length of secret key should be 16 for 128 bits key size!";
                        }
                        else if (Size == KeySize.Bit192 && Secret.Length != 24)
                        {
                            Error = "Length of secret key should be 24 for 192 bits key size!";
                        }
                        else if (Size == KeySize.Bit256 && Secret.Length != 32)
                        {
                            Error = "Length of secret key should be 32 for 256 bits key size!";
                        }
                        break;
                }
                return Error;
            }
            catch { return Error; }
        }
    }
}