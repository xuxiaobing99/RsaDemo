using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSADemo
{
     public class AESCode
    {
        public string Key { get; set; }
        public string Encrypt(string val)
        {
            if (string.IsNullOrEmpty(val))
                return null;
            using (AesManaged des = new AesManaged())
            {
                byte[] inputByteArray = Encoding.UTF8.GetBytes(val);
                byte[] _key;
                byte[] _iv;
                GeneralKeyIV(this.Key, out _key, out _iv);
                des.Key = _key;
                des.IV = _iv;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputByteArray, 0, inputByteArray.Length);
                        cs.FlushFinalBlock();
                        byte[] bytes = (byte[])ms.ToArray();
                        return Convert.ToBase64String(bytes);
                    }
                }
            }
        }
        public string Decrypt(string val)
        {
            if (string.IsNullOrEmpty(val))
                return null;


            using (AesManaged des = new AesManaged())
            {
                byte[] inputByteArray = Convert.FromBase64String(val);
                byte[] _key;
                byte[] _iv;
                GeneralKeyIV(this.Key, out _key, out _iv);
                des.Key = _key;
                des.IV = _iv;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputByteArray, 0, inputByteArray.Length);
                        cs.FlushFinalBlock();
                        return Encoding.UTF8.GetString(ms.ToArray());
                    }
                }
            }
        }
        public void GeneralKeyIV(string keyStr, out byte[] key, out byte[] iv)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(keyStr);
            key = SHA256Managed.Create().ComputeHash(bytes);
            iv = MD5.Create().ComputeHash(bytes);

            Console.WriteLine("key:"+key+"; iv:"+iv);
        }


    }
}
