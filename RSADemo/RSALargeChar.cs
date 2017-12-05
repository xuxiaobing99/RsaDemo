using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace RSADemo
{
    public class RSALargeChar
    {


        static public byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.  
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {


                    //Import the RSA Key information. This only needs  
                    //toinclude the public key information.  
                    RSA.ImportParameters(RSAKeyInfo);


                    //Encrypt the passed byte array and specify OAEP padding.    
                    //OAEP padding is only available on Microsoft Windows XP or  
                    //later.    
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException    
            //to the console.  
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);


                return null;
            }


        }


        static public byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.  
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs  
                    //to include the private key information.  
                    RSA.ImportParameters(RSAKeyInfo);


                    //Decrypt the passed byte array and specify OAEP padding.    
                    //OAEP padding is only available on Microsoft Windows XP or  
                    //later.    
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException    
            //to the console.  
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());


                return null;
            }


        }  





        public static String Encrypt(String plaintext, X509Certificate2 pubcrt)
        {
            X509Certificate2 _X509Certificate2 = pubcrt;
            using (RSACryptoServiceProvider RSACryptography = _X509Certificate2.PublicKey.Key as RSACryptoServiceProvider)
            {
                Byte[] PlaintextData = Encoding.UTF8.GetBytes(plaintext);
                int MaxBlockSize = RSACryptography.KeySize / 8 - 11;    //加密块最大长度限制  


                if (PlaintextData.Length <= MaxBlockSize)
                    return Convert.ToBase64String(RSACryptography.Encrypt(PlaintextData, false));


                using (MemoryStream PlaiStream = new MemoryStream(PlaintextData))
                using (MemoryStream CrypStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);


                    while (BlockSize > 0)
                    {
                        Byte[] ToEncrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToEncrypt, 0, BlockSize);


                        Byte[] Cryptograph = RSACryptography.Encrypt(ToEncrypt, false);
                        CrypStream.Write(Cryptograph, 0, Cryptograph.Length);


                        BlockSize = PlaiStream.Read(Buffer, 0, MaxBlockSize);
                    }


                    return Convert.ToBase64String(CrypStream.ToArray(), Base64FormattingOptions.None);
                }
            }
        }


        public static String Decrypt(String ciphertext, X509Certificate2 prvpfx)
        {
            X509Certificate2 _X509Certificate2 = prvpfx;
            using (RSACryptoServiceProvider RSACryptography = _X509Certificate2.PrivateKey as RSACryptoServiceProvider)
            {
                Byte[] CiphertextData = Convert.FromBase64String(ciphertext);
                int MaxBlockSize = RSACryptography.KeySize / 8;    //解密块最大长度限制  


                if (CiphertextData.Length <= MaxBlockSize)
                    return Encoding.UTF8.GetString(RSACryptography.Decrypt(CiphertextData, false));


                using (MemoryStream CrypStream = new MemoryStream(CiphertextData))
                using (MemoryStream PlaiStream = new MemoryStream())
                {
                    Byte[] Buffer = new Byte[MaxBlockSize];
                    int BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);


                    while (BlockSize > 0)
                    {
                        Byte[] ToDecrypt = new Byte[BlockSize];
                        Array.Copy(Buffer, 0, ToDecrypt, 0, BlockSize);


                        Byte[] Plaintext = RSACryptography.Decrypt(ToDecrypt, false);
                        PlaiStream.Write(Plaintext, 0, Plaintext.Length);


                        BlockSize = CrypStream.Read(Buffer, 0, MaxBlockSize);
                    }


                    return Encoding.UTF8.GetString(PlaiStream.ToArray());
                }
            }
        }


        private static X509Certificate2 RetrieveX509Certificate()
        {
            return null;    //检索用于 RSA 加密的 X509Certificate2 证书  
        }  

    }
}
