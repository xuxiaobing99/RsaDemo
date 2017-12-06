
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;


namespace RSADemo
{
    public partial class Form1 : Form
    {


        private string publicKey1 = "";
        private string privateKey1 = "";

        private string basePathToStoreKeys;


        private const int RsaKeySize = 2048;
        private byte[] publicInfoByte = null;
        private byte[] privateInfoByte = null;
        IAsymmetricBlockCipher cipher = new RsaEngine();

        private static RSACryptoServiceProvider RSA = null;
        public string key { get; set; }

        public Form1()
        {
            InitializeComponent();
        }


        /// <summary>  
        /// 对ExportCspBlob(false)方法到处的私钥进行解析，提取私钥参数  
        /// </summary>  
        /// <param name="cspblobPublicKey">RSA.ExportCspBlob(false)得到的包含私钥信息</param>  
        /// <returns>公钥模数</returns>  
        public static byte[] PublicKeyResolve(byte[] cspblobPublicKey)
        {
            byte[] modulus = new byte[128];
            Array.Reverse(cspblobPublicKey, 0, cspblobPublicKey.Length);
            Buffer.BlockCopy(cspblobPublicKey, 0, modulus, 0, 128);
            return modulus;
        }

        /// <summary>  
        /// 对ExportCspBlob(true)方法到处的私钥进行解析，提取私钥参数  
        /// </summary>  
        /// <param name="cspblobPrivateKey">RSA.ExportCspBlob(true)得到的包含私钥信息</param>  
        /// <returns>私钥参数</returns>  
        public static Dictionary<string, byte[]> PrivateKeyResolve(byte[] cspblobPrivateKey)
        {
            Dictionary<string, byte[]> privateKeyParameters = new Dictionary<string, byte[]>();

            Array.Reverse(cspblobPrivateKey, 0, cspblobPrivateKey.Length);
            int offset = 0;
            byte[] part = new byte[128];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, offset, part.Length);
            privateKeyParameters.Add("D", part);

            offset += part.Length;
            part = new byte[64];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("INVERSEQ", part);

            offset += part.Length;
            part = new byte[64];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("DQ", part);

            offset += part.Length;
            part = new byte[64];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("DP", part);

            offset += part.Length;
            part = new byte[64];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("Q", part);

            offset += part.Length;
            part = new byte[64];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("P", part);

            offset += part.Length;
            part = new byte[128];
            Buffer.BlockCopy(cspblobPrivateKey, offset, part, 0, part.Length);
            privateKeyParameters.Add("MODULUS", part);
            return privateKeyParameters;

            string s = "";
        }












        /////
        /// <summary>
        /// 生成公钥私钥
        /// </summary>
        public void GenerateKeys()
        {
            //using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
            //{
            //    try
            //    {
            //        // 获取私钥和公钥。
            //        publicKey = rsa.ToXmlString(false);
            //        privateKey = rsa.ToXmlString(true);
            //    }
            //    finally
            //    {
            //        rsa.PersistKeyInCsp = false;
            //    }
            //}

            //RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            //RsaKeyGenerationParameters rsaKeyGenerationParameters = new RsaKeyGenerationParameters(BigInteger.ValueOf(3), new Org.BouncyCastle.Security.SecureRandom(), 1024, 25);
            //rsaKeyPairGenerator.Init(rsaKeyGenerationParameters);//初始化参数  
            //AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();
            //AsymmetricKeyParameter AsypublicKey = keyPair.Public;//公钥  
            //AsymmetricKeyParameter AsyprivateKey = keyPair.Private;//私钥  

            //SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AsypublicKey);
            //PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(AsyprivateKey);

            //Asn1Object asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
            //publicInfoByte = asn1ObjectPublic.GetEncoded();
            //Asn1Object asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
            //privateInfoByte = asn1ObjectPrivate.GetEncoded();
            //// 获取私钥和公钥。
            //string publicKey = Convert.ToBase64String(publicInfoByte);
            //string privateKey = Convert.ToBase64String(privateInfoByte);




            //这里可以将密钥对保存到本地  
            //Console.WriteLine("PublicKey:\n" + publicKey);
            //Console.WriteLine("PrivateKey:\n" + privateKey);

             key = GetRandomString(16);
   
        }


        //获得随机产生的字符，长度 为   lenght
        public string GetRandomString(int lenght)
        {
            Random rd = new Random();
            string str = "abcdefghijklmnopqrstuvwxyz";
            string result = "";
            for (int i = 0; i < lenght; i++)
            {
                result += str[rd.Next(str.Length)];
            }
            return result;
        }


        /// <summary>
        /// RSA公钥文件加密纯文本
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns>表示加密数据的64位编码字符串</returns>
        public string Encrypt(string plainText)
        {

            try
            {
                //plainText = MD5Encode(plainText);
                //加密
                if (publicInfoByte == null)
                {
                    Console.WriteLine("请先生成密钥");
                    Console.Read();
                    return "";
                }
                Asn1Object pubKeyObj = Asn1Object.FromByteArray(publicInfoByte); //这里也可以从流中读取，从本地导入  
                AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(pubKeyObj));
                cipher.Init(true, pubKey); //true表示加密  
                //加密 
                Console.WriteLine("\n明文：" + plainText);
                byte[] encryptData = cipher.ProcessBlock(Encoding.UTF8.GetBytes(plainText), 0, Encoding.UTF8.GetBytes(plainText).Length);
                string crystr = Convert.ToBase64String(encryptData);
                Console.WriteLine("密文:" + crystr);
                return crystr;
            }
            catch (Exception e)
            {
                return null;
            }

        }


        /// <summary>
        /// 解密文本
        /// </summary>
        /// <param name="encryptData"></param>
        /// <returns></returns>
        public string Decrypt(string encryptData)
        {
            try
            {
                //解密  
                if (privateInfoByte == null)
                {
                    Console.WriteLine("请先生成密钥");
                    Console.Read();
                    return "";
                }
                AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
                cipher.Init(false, priKey);//false表示解密  
                string decryptData = Encoding.UTF8.GetString(cipher.ProcessBlock(Convert.FromBase64String(encryptData), 0, Convert.FromBase64String(encryptData).Length));
                Console.WriteLine("解密后数据：" + decryptData);
                Console.Read();
                return decryptData;
            }
            catch (Exception e)
            {
                return null;
            }
        }

        //生成密钥
        private void button1_Click(object sender, EventArgs e)
        {
            GenerateKeys();

            //GenerateKeys1();

            //string key = "aaaabbbbaaaabbbb";
            //string iv = key;
            //string gggg = "sfefsaewgfse";
            //string hexgggg = RSACrypto.DESEnCode(gggg, key);
            //string returnggg = RSACrypto.DESDeCode(hexgggg, key);

            // AESCode aescode=new AESCode();
            //aescode.Key = key;
            // string encodestr=  aescode.Encrypt(gggg);
            //string retustr = aescode.Decrypt(encodestr);

        }



        //public string StrToHex(string mStr) //返回处理后的十六进制字符串
        //{
        //    return BitConverter.ToString(
        //    ASCIIEncoding.Default.GetBytes(mStr)).Replace("-", " ");
        //}
        ///* StrToHex */
        //public string HexToStr(string mHex) // 返回十六进制代表的字符串
        //{
        //    mHex = mHex.Replace(" ", "");
        //    if (mHex.Length <= 0) return "";
        //    byte[] vBytes = new byte[mHex.Length / 2];
        //    for (int i = 0; i < mHex.Length; i += 2)
        //        if (!byte.TryParse(mHex.Substring(i, 2), NumberStyles.HexNumber, null, out vBytes[i / 2]))
        //            vBytes[i / 2] = 0;
        //    return ASCIIEncoding.Default.GetString(vBytes);
        //}

        //加密文本框内容
        private void Button2_Click(object sender, EventArgs e)
        {
            //var encryptedString = Encrypt(textBox1.Text);
            //textBox2.Text = encryptedString;
            //var decryptedString = signData(textBox2.Text);
            //textBox2.Text = decryptedString;

            if (key == null|| string.IsNullOrEmpty(key))
            {
                Console.WriteLine("请先生成随机16字符串的密钥");
                return;
            }

            string gggg = this.textBox1.Text;
            string hexgggg = RSACrypto.DESEnCode(gggg.Trim(), key);
            this.textBox2.Text = hexgggg;
            Console.WriteLine("EntryData:" + hexgggg);
     

        }

        //解密文本框内容
        private void button3_Click(object sender, EventArgs e)
        {
            //var decryptedString = Decrypt(textBox2.Text);

            //textBox2.Text = decryptedString;

            //string user = "limt";
            //string time = "2010-12-01 11:00:00";
            //string data = user + time;
            //string endata = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
            //var decryptedString = verifySignature(textBox2.Text, endata);


            if (key == null || string.IsNullOrEmpty(key))
            {
                Console.WriteLine("请先生成随机16字符串的密钥");
                return;
            }
            string decryptedString = this.textBox2.Text;
            string returnggg = (RSACrypto.DESDeCode(decryptedString, key)).Replace("\0", "");
            Console.WriteLine("解密后数据：" + returnggg);
            Console.Read();
            this.textBox2.Text = returnggg;

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        /// <summary>
        /// 对java过来的数据进行解密
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button4_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(this.textBox5.Text))
                {
                    Console.WriteLine("请先填写对方公司的16字符串的密钥");
                    return;
                }
                string encryptData = this.textBox3.Text;
                string returnggg = (RSACrypto.DESDeCode(encryptData, this.textBox5.Text)).Replace("\0", "");
                Console.WriteLine("解密后数据：" + returnggg);
                Console.Read();
                this.textBox4.Text = returnggg;


                //privateInfoByte = Convert.FromBase64String(this.textBox5.Text);

                //AsymmetricKeyParameter priKey = PrivateKeyFactory.CreateKey(privateInfoByte);
                //cipher.Init(false, priKey);//false表示解密  
                //string decryptData = Encoding.UTF8.GetString(cipher.ProcessBlock(Convert.FromBase64String(encryptData), 0, Convert.FromBase64String(encryptData).Length));
            }
            catch (Exception ex)
            {
                this.textBox4.Text = "";
            }
        }








        //public void GenerateKeys1()
        //{
        //    RSA = new RSACryptoServiceProvider(RsaKeySize);


            //if (type == RSAType.ITDMS)
            //{
            //    RSAKeyInfo = new RSAParameters();
            //    RSAKeyInfo.Modulus = Convert.FromBase64String(PUB_KEY_MODULES);
            //    RSAKeyInfo.Exponent = Convert.FromBase64String(PUB_KEY_EXP);
            //    RSA.ImportParameters(RSAKeyInfo);
            //}
            //else //type == RSAType.RSP
            //{ 
            //RSA.FromXmlString(NET_PRIVATE_KEY);
            //}

            // 获取私钥和公钥。
        //    publicKey1 = RSA.ToXmlString(false);
        //    privateKey1 = RSA.ToXmlString(true);

        //    // 保存到磁盘
        //    //File.WriteAllText(Path.Combine(path, publicKeyFileName), publicKey);
        //    //File.WriteAllText(Path.Combine(path, privateKeyFileName), privateKey);

        //    Console.Write("publicKey1:\r\n:" + publicKey1);
        //    Console.Write("privateKey1:\r\n:" + privateKey1);


        //}

        /// <summary>
        /// 用给定路径的RSA公钥文件加密纯文本。
        /// </summary>
        /// <param name="plainText">要加密的文本</param>
        /// <param name="pathToPublicKey">用于加密的公钥路径.</param>
        /// <returns>表示加密数据的64位编码字符串.</returns>
        //public string Encrypt1(string plainText)
        //{
        //    using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
        //    {
        //        try
        //        {
        //            //加载公钥

        //            rsa.FromXmlString(publicKey1);

        //            var bytesToEncrypt = System.Text.Encoding.Unicode.GetBytes(plainText);

        //            var bytesEncrypted = rsa.Encrypt(bytesToEncrypt, false);

        //            return Convert.ToBase64String(bytesEncrypted);
        //        }
        //        finally
        //        {
        //            rsa.PersistKeyInCsp = false;
        //        }
        //    }
        //}

        ///// <summary>
        ///// Decrypts encrypted text given a RSA private key file path.给定路径的RSA私钥文件解密 加密文本
        ///// </summary>
        ///// <param name="encryptedText">加密的密文</param>
        ///// <param name="pathToPrivateKey">用于加密的私钥路径.</param>
        ///// <returns>未加密数据的字符串</returns>
        //public string Decrypt1(string encryptedText)
        //{
        //    using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
        //    {
        //        try
        //        {
        //            var privateXmlKey = File.ReadAllText(privateKey1);
        //            rsa.FromXmlString(privateXmlKey);

        //            var bytesEncrypted = Convert.FromBase64String(encryptedText);

        //            var bytesPlainText = rsa.Decrypt(bytesEncrypted, false);

        //            return System.Text.Encoding.Unicode.GetString(bytesPlainText);
        //        }
        //        finally
        //        {
        //            rsa.PersistKeyInCsp = false;
        //        }
        //    }
        //}








        //public string signData(string dataToBeSigned)
        //{
        //    byte[] data = Encoding.UTF8.GetBytes(dataToBeSigned);

        //    byte[] endata = RSA.SignData(data, "SHA1");

        //    return Convert.ToBase64String(endata);

        //}
        /// <summary>
        /// Verifies the signature for a given data.
        /// </summary>
        /// <param name="signature">Signature data in Base64</param>
        /// <param name="signedData">Original data in BASE64</param>
        /// <returns>True if signature is valid else False</returns>
        //public bool verifySignature(string signature, string signedData)
        //{
        //    byte[] sign = Convert.FromBase64String(signature);
        //    return verifySignature(sign, signedData);
        //}
        /// <summary>
        /// Verifies the signature for a given data.
        /// </summary>
        /// <param name="signature">The signature </param>
        /// <param name="signedData">Original data in Base64</param>
        /// <returns></returns>
        //public bool verifySignature(byte[] signature, string signedData)
        //{
        //    try
        //    {
        //        byte[] hash = Convert.FromBase64String(signedData);
        //        if (RSA.VerifyData(hash, "SHA1", signature))
        //        {
        //            return true;
        //        }
        //        else
        //        {
        //            //Console.WriteLine("The signature is not valid.");
        //            return false;
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine(e.Message);
        //        return false;
        //    }
        //}

//        private void button5_Click(object sender, EventArgs e)
//        {
//            try
//            {
//                //Create a UnicodeEncoder to convert between byte array and string.  
//                UnicodeEncoding ByteConverter = new UnicodeEncoding();

//                String plaintext = "Data to Encrypt";
//                //Create byte arrays to hold original, encrypted, and decrypted data.  
//                byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt");
//                byte[] encryptedData;
//                byte[] decryptedData;

//                string publickey = @"<RSAKeyValue>
//<Modulus>27O6xpQnmv7f4U5JFOUc2+KmVfMlCzKBBrJTci3alkEL+K+JRIqlv4uIDPdUhTifHNVCRANUs+hEesG2XiAVHM9QSQZ5BjZcW4zyLZWdjWdrSxu4kstBrf09n7sqLTg/oIfL01jAAg6IyYo2W3ll7lieKD9kTKgKmr2AIk2vZG6Hy0D6vZfc5dOLl9drJYQDol8QntWR7jMA0NvhxP3ApeqgrGuC2lkbzuhb2EKLbryMRYKpbMmzJUZZoRhLQzV4rjyqRpx/difbw9iTVyIxQ+GWMONgAHPtUg8hQw6txmtIY68YjIIMojPrIF8KKYXF84aOflfyHQgVI3apyqSRqw==
//</Modulus>
//<Exponent>AQAB</Exponent>
//</RSAKeyValue>";

//                string privatekey = @"<RSAKeyValue><Modulus>27O6xpQnmv7f4U5JFOUc2+KmVfMlCzKBBrJTci3alkEL+K+JRIqlv4uIDPdUhTifHNVCRANUs+hEesG2XiAVHM9QSQZ5BjZcW4zyLZWdjWdrSxu4kstBrf09n7sqLTg/oIfL01jAAg6IyYo2W3ll7lieKD9kTKgKmr2AIk2vZG6Hy0D6vZfc5dOLl9drJYQDol8QntWR7jMA0NvhxP3ApeqgrGuC2lkbzuhb2EKLbryMRYKpbMmzJUZZoRhLQzV4rjyqRpx/difbw9iTVyIxQ+GWMONgAHPtUg8hQw6txmtIY68YjIIMojPrIF8KKYXF84aOflfyHQgVI3apyqSRqw==</Modulus><Exponent>AQAB</Exponent><P>+wKi/UEftfymbsDp4RJNFuBZT8PeS9juIAQqInKZ4LLaOyYSe1gecjWbyGW+cRUy3aLnSbIIXI+OgcauYuMoyc/tnF5MSKjIJnBCdD6zE2tfSPivT/0XSN6IzP+QO7r3h9GoS1vzSthSpPV73QtrSkkTAOJmCZbG7x9pfPFwT7M=</P><Q>4BHE0jyVOW1XwmSVrvNNNdUp/tdgwrpk9Dli2SKTxTt1mp9GJO/2AxPg80VpwTCr5yEAttWz820K0l3JWrCpuhO1h6++hm9R9Zfsn4AgGg/GIgnkvE0MyEqDrS/erVmvHxIse1LHZzu9iYUKrhvGDB5gbQSN6riZ0DDk0kVh+ik=</Q><DP>qLPR9eKiPH8tIPz5c/MH6tsoS6r6KgIHsW77HqHleBbdA6oH++xyshIDvMFdKMW1pS7KwkYsxoEZp3FwXTgNfu4H5fOe06rUsrj6gQRu+RtONE4oDdutnaUrTpRpTSvRF/C6asPHFcOkcAgpkpwNJSVN52dCaylyVN7I2FexQ28=</DP><DQ>weIeMNyDMwHOIkLu0kds09vzTrQG4fhvSnQteD1XKB7fEEApbeTFNryItXemnqgC1yfTemFIKKZ96rGEfZjIBF7xgMstTR4eCSjAcvNm06Y6h1GQPu9c1CLF9aGqSM2FnpkXLE7ghA9JXilkqGsX33yZazu5oRTC40areNbYhKE=</DQ><InverseQ>946Mr4G/VtGF7K3LZ6mveh7fqkgzeeAgZK0jep/z/g0R+8x/96VOEfkVyMSbeg3WqKgDSq8yRbyXARi+cyZFmyORO0MCIEsMrciwrm6qf45+VCDcq6bAAQdx3PiMfzv6LuUm0eMjXjDVG9Jk8VFViElCuBsG4QkF3FiXSuRL8Kc=</InverseQ><D>yPIcdSBxERzpXEOkKE5eFOe6x4Y6bYFl7eAQ3q/968vWzUCQRnahnw5aA7H8RlVBgrezgk2hnWNlrvmaeYDSjqU3g3M+ImZ6FupVX0gm8HyU7/+M1AbALgkf4gboTq/R0lwiG05jX/43Mk8N5KCmkFfRYHKKpGpWOK32kmmHcEzNs/fxzN8b41WDAm5E5212eDGPxIRX5DhHQ3y4oSawKRqVVsA5JxtPS1zjBh3BStV+cpYowEd8WGnYSOL4dGAIEX5V+0uVipD8uwIOyBoNFf61aAf6QxfMAF6Cvjo1R3rXU/81Panms3cQRog7sr/TvsSH3LACJaVVpGqWXfnI4Q==</D></RSAKeyValue>";
//                //X509Certificate2 pubcrt = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "bfkey.cer");
                //RSACryptoServiceProvider pubkey = (RSACryptoServiceProvider)pubcrt.PublicKey.Key;
                //X509Certificate2 prvcrt = new X509Certificate2(AppDomain.CurrentDomain.BaseDirectory + "bfkey.pfx", "123456789", X509KeyStorageFlags.Exportable);
                //RSACryptoServiceProvider prvkey = (RSACryptoServiceProvider)prvcrt.PrivateKey;

                //string encryptedData1 = RSACrypto.RsaEncrypt(plaintext, publickey);
                //Console.WriteLine("Encrypted plaintext: {0}", encryptedData1);

                //string decryptedData1 = RSACrypto.RsaDecrypt(encryptedData1, privatekey);

                //decryptedData = RSALargeChar.RSADecrypt(encryptedData, prvkey.ExportParameters(true), false);


                //Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));


                //加密长内容  
                //                String data1 = @"RSA 是常用的非对称加密算法。最近使用时却出现了“不正确的长度”的异常，研究发现是由于待加密的数据超长所致。  
                //　　                    .NET Framework 中提供的 RSA 算法规定：  
                //　　                    待加密的字节数不能超过密钥的长度值除以 8 再减去 11（即：RSACryptoServiceProvider.KeySize / 8 - 11），而加密后得到密文的字节数，正好是密钥的长度值除以 8（即：RSACryptoServiceProvider.KeySize / 8）。  
                //　　                    所以，如果要加密较长的数据，则可以采用分段加解密的方式，实现方式如下：";
                //                string encrypt = RSALargeChar.Encrypt(data1, pubcrt);
                //                Console.WriteLine("Encrypted plaintext: {0}", encrypt);
                //                string decrypt = RSALargeChar.Decrypt(encrypt, prvcrt);
                //                Console.WriteLine("Decrypted plaintext: {0}", decrypt);

                //prvkey.Clear();
                //pubkey.Clear();
                //Console.Read();
            //}
            //catch (ArgumentNullException)
            //{
            //    //Catch this exception in case the encryption did  
            //    //not succeed.  
            //    Console.WriteLine("Encryption failed.");


            //}
        //}

    }
}
