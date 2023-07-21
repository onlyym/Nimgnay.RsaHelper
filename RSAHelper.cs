using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;


namespace Nimgnay.RsaLibrary
{
    /// <summary>
    /// RSA帮助类
    /// author:Nimgnay
    /// 2023-06-28
    /// </summary>

    public class RSAHelper
    {
        private readonly RSA _privateKeyRsaProvider;
        private readonly RSA _publicKeyRsaProvider;
        private readonly HashAlgorithmName _hashAlgorithmName;
        private readonly Encoding _encoding;
        private readonly PrivateKeyType _keyFormat;
        /// <summary>
        /// 实例化RSAHelper
        /// </summary>
        /// <param name="rsaType">加密算法类型 RSA SHA1;RSA2 SHA256 密钥长度至少为2048</param>
        /// <param name="encoding">编码类型</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">私钥类型</param>
        public RSAHelper(RSAType rsaType, Encoding encoding, string privateKey, string publicKey, PrivateKeyType keyFormat)
        {
            _encoding = encoding;
            _keyFormat = keyFormat;
            if (!string.IsNullOrEmpty(privateKey))
            {
                _privateKeyRsaProvider = CreateRsaProviderFromPrivateKey(privateKey);
            }

            if (!string.IsNullOrEmpty(publicKey))
            {
                _publicKeyRsaProvider = CreateRsaProviderFromPublicKey(publicKey);
            }

            _hashAlgorithmName = rsaType == RSAType.RSA ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256;
        }

        #region 使用私钥签名

        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <returns></returns>
        public string Sign(string data)
        {
            if (_privateKeyRsaProvider == null)
            {
                throw new Exception("_privateKeyRsaProvider is null");
            }
            byte[] dataBytes = _encoding.GetBytes(data);

            var signatureBytes = _privateKeyRsaProvider.SignData(dataBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);

            return Convert.ToBase64String(signatureBytes);
        }

        #endregion

        #region 使用公钥验证签名

        /// <summary>
        /// 使用公钥验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="sign">签名</param>
        /// <returns></returns>
        public bool Verify(string data, string sign)
        {
            if (_publicKeyRsaProvider == null)
            {
                throw new Exception("_publicKeyRsaProvider is null");
            }
            byte[] dataBytes = _encoding.GetBytes(data);
            byte[] signBytes = Convert.FromBase64String(sign);

            var verify = _publicKeyRsaProvider.VerifyData(dataBytes, signBytes, _hashAlgorithmName, RSASignaturePadding.Pkcs1);

            return verify;
        }

        #endregion

 



        #region 加密 _publicKeyRsaProvider

        /// <summary>
        /// 使用公钥加密(自适应加密字符串长度)
        /// </summary>
        /// <param name="content">待加密字符串</param>
        /// <param name="padding">加密方式</param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public string Encrypt(string encryptstring, RSAEncryptionPadding padding)
        {
            if (_publicKeyRsaProvider == null)
            {
                throw new Exception("_publicKeyRsaProvider is null");
            }
            byte[] data = (new UnicodeEncoding()).GetBytes(encryptstring); //要加密的数据

            int bufferSize = (_publicKeyRsaProvider.KeySize >> 3) - 11;
            string result = string.Empty;
            if (data.Length > bufferSize)
                result = RSAEncryptLong(data, bufferSize, padding);
            else
                result = RSAEncryptNormal(data, padding);
            return result;
        }
        /// <summary>
        /// 加密(正常长度)
        /// </summary>
        /// <param name="data"></param>
        /// <param name="bufferSize"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        private string RSAEncryptLong(byte[] data, int bufferSize, RSAEncryptionPadding padding)
        {
            byte[] buffer = new byte[bufferSize];
            using MemoryStream msInput = new MemoryStream(data);
            using MemoryStream msOutput = new MemoryStream();
            int readLen = msInput.Read(buffer, 0, bufferSize);
            while (readLen > 0)
            {
                byte[] dataToEnc = new byte[readLen];
                Array.Copy(buffer, 0, dataToEnc, 0, readLen);
                byte[] encData = _publicKeyRsaProvider.Encrypt(dataToEnc, padding);
                msOutput.Write(encData, 0, encData.Length);
                readLen = msInput.Read(buffer, 0, bufferSize);
            }
            byte[] result = msOutput.ToArray();    //得到加密结果
            return ByteSToBase64String(result);
        }
        /// <summary>
        /// 加密(超长长度)
        /// </summary>
        /// <param name="data"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        private string RSAEncryptNormal(byte[] data, RSAEncryptionPadding padding)
        {

            byte[] encrypt = _publicKeyRsaProvider.Encrypt(data, padding);
            return ByteSToBase64String(encrypt);
        }


        #endregion




        #region 解密 _privateKeyRsaProvider


        /// <summary>
        /// 解密，自适应长度解密
        /// </summary>
        /// <param name="decryptstring">待解密字符串</param>
        /// <param name="padding">解密方式</param>
        /// <returns></returns>
        public string RSADecrypt( string decryptstring, RSAEncryptionPadding padding)
        {
            if (_privateKeyRsaProvider == null)
            {
                throw new Exception("_privateKeyRsaProvider is null");
            }

            byte[] dataEnc = Convert.FromBase64String(decryptstring); //加载密文
            int keySize =_privateKeyRsaProvider.KeySize >> 3;
            string result = string.Empty;
            if (dataEnc.Length > keySize)
                result = RSADecryptLong( dataEnc, keySize, padding);
            else
                result = RSADecryptNormal( dataEnc, padding);
            return result;
        }

       /// <summary>
       /// 正常长度解密
       /// </summary>
       /// <param name="dataEnc"></param>
       /// <param name="padding"></param>
       /// <returns></returns>
        private string RSADecryptNormal(byte[] dataEnc, RSAEncryptionPadding padding)
        {
            byte[] DypherTextBArray = _privateKeyRsaProvider.Decrypt(dataEnc, padding);
            return (new UnicodeEncoding()).GetString(DypherTextBArray);
        }
       /// <summary>
       /// 超长字符串解密
       /// </summary>
       /// <param name="dataEnc"></param>
       /// <param name="keySize"></param>
       /// <param name="padding"></param>
       /// <returns></returns>
        private string RSADecryptLong(byte[] dataEnc, int keySize, RSAEncryptionPadding padding)
        {
            byte[] buffer = new byte[keySize];
            using MemoryStream msInput = new MemoryStream(dataEnc);
            using MemoryStream msOutput = new MemoryStream();
            int readLen = msInput.Read(buffer, 0, keySize);
            while (readLen > 0)
            {
                byte[] dataToDec = new byte[readLen];
                Array.Copy(buffer, 0, dataToDec, 0, readLen);
                byte[] decData = _privateKeyRsaProvider.Decrypt(dataToDec, padding);
                msOutput.Write(decData, 0, decData.Length);
                readLen = msInput.Read(buffer, 0, keySize);
            }
            byte[] result = msOutput.ToArray();    //得到解密结果
            return (new UnicodeEncoding()).GetString(result);
        }


        #endregion




        /// <summary>
        /// byte[] 转base64字符串
        /// </summary>
        /// <param name="encrypt"></param>
        /// <returns></returns>
        private string ByteSToBase64String(byte[] encrypt)
        {
            return Convert.ToBase64String(encrypt);
        }


        #region 使用私钥创建RSA实例

        /// <summary>
        /// 使用私钥创建RSA实例
        /// </summary>
        /// <param name="privateKeyPem"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public RSA CreateRsaProviderFromPrivateKey(string privateKeyPem)
        {
            //转换为普通字符串
            privateKeyPem = privateKeyPem.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "").Replace("\r", "").Replace("\n", "").Trim();
            privateKeyPem = privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\r", "").Replace("\n", "").Trim();


            RSA rsa = RSA.Create();
            //根据私钥类型使用不同的私钥导入方式
            if (_keyFormat == PrivateKeyType.PKCS8)
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyPem), out _);
            else if (_keyFormat == PrivateKeyType.PKCS1)
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKeyPem), out _);
            else
                throw new Exception("只支持PKCS8，PKCS1");

            return rsa;
        }

        #endregion

        #region 使用公钥创建RSA实例
        /// <summary>
        /// 使用公钥创建RSA实例
        /// </summary>
        /// <param name="publicKeyString"></param>
        /// <returns></returns>
        public RSA CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            //转换为普通字符串
            publicKeyString = publicKeyString.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\r", "").Replace("\n", "").Trim();

            RSA rsa = RSA.Create();
            //公钥分为PEM格式和DER格式  PEM格式则是包含 类似 -----BEGIN PUBLIC KEY----- 等字符串的公钥
            // DER格式用ImportSubjectPublicKeyInfo 导入公钥
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyString), out _);

            // PEM格式用ImportFromPem导入
            //rsa.ImportFromPem(publicKeyString);

            return rsa;

        }

        #endregion


    }

    /// <summary>
    /// 私钥类型 
    /// </summary>
    public enum PrivateKeyType
    {
        /// <summary>
        /// PKCS8
        /// </summary>
        PKCS8,
        /// <summary>
        /// PKCS1
        /// </summary>
        PKCS1 
    }

    /// <summary>
    /// RSA算法类型
    /// </summary>
    public enum RSAType
    {
        /// <summary>
        /// SHA1
        /// </summary>
        RSA = 0,
        /// <summary>
        /// RSA2 密钥长度至少为2048
        /// SHA256
        /// </summary>
        RSA2
    }

}
