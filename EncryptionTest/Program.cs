using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string Password = "ehhh";
            string Salt = "salt";
            string IV = System.Text.Encoding.Default.GetString(GetIV());
            string encrypted = AESEncrypt("fool", Password, Salt, "SHA1", 5, IV, 256);
            Console.WriteLine(encrypted);
            

            Console.WriteLine(AESDecrypt(encrypted, Password, Salt, "SHA1", 5, IV, 256));
            Console.ReadLine();
                
        }

        static void SymetricEncryption()
        {
            try
            {
            //Create a TCP connection to a listening TCP process.
                //Use "localhost" to specify the current computer or
                //replace "localhost" with the IP address of the 
                //listening process.  
                TcpClient TCP = new TcpClient("localhost", 11000);

                //Create a network stream from the TCP connection. 
                NetworkStream NetStream = TCP.GetStream();

                //Create a new instance of the RijndaelManaged class
                // and encrypt the stream.
                RijndaelManaged RMCrypto = new RijndaelManaged();

                byte[] Key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
                byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

                //Create a CryptoStream, pass it the NetworkStream, and encrypt 
                //it with the Rijndael class.
                CryptoStream CryptStream = new CryptoStream(NetStream,
                RMCrypto.CreateEncryptor(Key, IV),
                CryptoStreamMode.Write);

                //Create a StreamWriter for easy writing to the 
                //network stream.
                StreamWriter SWriter = new StreamWriter(CryptStream);

                //Write to the stream.
                SWriter.WriteLine("Hello World!");

                //Inform the user that the message was written
                //to the stream.
                Console.WriteLine("The message was sent.");

                //Close all the connections.
                SWriter.Close();
                CryptStream.Close();
                NetStream.Close();
                TCP.Close();
            }
            catch
            {
                //Inform the user that an exception was raised.
                Console.WriteLine("The connection failed.");
            }
        }

        static void AssymetricEncryption()
        {
            //Initialize the byte arrays to the public key information.
            byte[] PublicKey = {214,46,220,83,160,73,40,39,201,155,19,202,3,11,191,178,56,
            74,90,36,248,103,18,144,170,163,145,87,54,61,34,220,222,
            207,137,149,173,14,92,120,206,222,158,28,40,24,30,16,175,
            108,128,35,230,118,40,121,113,125,216,130,11,24,90,48,194,
            240,105,44,76,34,57,249,228,125,80,38,9,136,29,117,207,139,
            168,181,85,137,126,10,126,242,120,247,121,8,100,12,201,171,
            38,226,193,180,190,117,177,87,143,242,213,11,44,180,113,93,
            106,99,179,68,175,211,164,116,64,148,226,254,172,147};

            byte[] Exponent = { 1, 0, 1 };

            //Create values to store encrypted symmetric keys.
            byte[] EncryptedSymmetricKey;
            byte[] EncryptedSymmetricIV;

            //Create a new instance of the RSACryptoServiceProvider class.
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

            //Create a new instance of the RSAParameters structure.
            RSAParameters RSAKeyInfo = new RSAParameters();

            //Set RSAKeyInfo to the public key values. 
            RSAKeyInfo.Modulus = PublicKey;
            RSAKeyInfo.Exponent = Exponent;

            //Import key parameters into RSA.
            RSA.ImportParameters(RSAKeyInfo);

            //Create a new instance of the RijndaelManaged class.
            RijndaelManaged RM = new RijndaelManaged();

            //Encrypt the symmetric key and IV.
            EncryptedSymmetricKey = RSA.Encrypt(RM.Key, false);
            EncryptedSymmetricIV = RSA.Encrypt(RM.IV, false);
        }

        public static byte[] GetIV()
        {
            byte[] randomArray = new byte[16];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(randomArray);
            return randomArray;
        }

        public static string AESEncrypt(string PlainText, string Password, string Salt, string HashAlgorithm, int PasswordIterations, string InitialVector, int KeySize)
        {
            if (string.IsNullOrEmpty(PlainText))
            {
                return "The Text to be Decryped by AES must not be null...";
            }
            else if (string.IsNullOrEmpty(Password))
            {
                return "The Password for AES Decryption must not be null...";
            }
            byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
            byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
            byte[] PlainTextBytes = Encoding.UTF8.GetBytes(PlainText);
            PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
            byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);

            RijndaelManaged SymmetricKey = new RijndaelManaged();

            SymmetricKey.Mode = CipherMode.CBC;

            byte[] CipherTextBytes = null;

            using (ICryptoTransform Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, InitialVectorBytes))
            {

                using (MemoryStream MemStream = new MemoryStream())
                {
                    using (CryptoStream CryptoStream = new CryptoStream(MemStream, Encryptor, CryptoStreamMode.Write))
                    {
                        CryptoStream.Write(PlainTextBytes, 0, PlainTextBytes.Length);
                        CryptoStream.FlushFinalBlock();
                        CipherTextBytes = MemStream.ToArray();
                        MemStream.Close();
                        CryptoStream.Close();
                    }
                }
            }
            SymmetricKey.Clear();
            return Convert.ToBase64String(CipherTextBytes);

        }


        // <summary>  
        // Decrypts a string          
        // </summary>        
        // <param name="CipherText">Text to be decrypted</param>         
        // <param name="Password">Password to decrypt with</param>         
        // <param name="Salt">Salt to decrypt with</param>          
        // <param name="HashAlgorithm">Can be either SHA1 or MD5</param>         
        // <param name="PasswordIterations">Number of iterations to do</param>          
        // <param name="InitialVector">Needs to be 16 ASCII characters long</param>          
        // <param name="KeySize">Can be 128, 192, or 256</param>          
        // <returns>A decrypted string</returns>        
        public static string AESDecrypt(string CipherText, string Password, string Salt, string HashAlgorithm, int PasswordIterations, string InitialVector, int KeySize)
        {
            if (string.IsNullOrEmpty(CipherText))
            {
                return "The Text to be Decryped by AES must not be null...";
            }
            else if (string.IsNullOrEmpty(Password))
            {
                return "The Password for AES Decryption must not be null...";
            }
            byte[] InitialVectorBytes = Encoding.ASCII.GetBytes(InitialVector);
            byte[] SaltValueBytes = Encoding.ASCII.GetBytes(Salt);
            byte[] CipherTextBytes = Convert.FromBase64String(CipherText);
            PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(Password, SaltValueBytes, HashAlgorithm, PasswordIterations);
            byte[] KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
            RijndaelManaged SymmetricKey = new RijndaelManaged();
            SymmetricKey.Mode = CipherMode.CBC;
            byte[] PlainTextBytes = new byte[CipherTextBytes.Length];
            int ByteCount = 0;
            try
            {

                using (ICryptoTransform Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, InitialVectorBytes))
                {
                    using (MemoryStream MemStream = new MemoryStream(CipherTextBytes))
                    {
                        using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
                        {
                            ByteCount = CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
                            MemStream.Close();
                            CryptoStream.Close();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                return "Please Enter the Correct Password and Salt..." + "The Following Error Occured: " + "/n" + e;
            }
            SymmetricKey.Clear();
            return Encoding.UTF8.GetString(PlainTextBytes, 0, ByteCount);

        }
    }
}
