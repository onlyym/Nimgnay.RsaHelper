## **说明**


| 加签解签说明 | 加解密说明 |
| ------- | ------- |
| 私钥加签，公钥解签方式       |    公钥加密，私钥解密方式     |




### 使用方式
~~~~
	  //**实例化hlper对象**  指定RSA算法方式，字符编码，公私钥及私钥类型

	  首先该工具类支持正常的RSA加签解签，加密解密， 
	  一定要搞清楚自己需求是加签解签，还是加密解密，这是两个不同的东西
	  一般的方式为 私钥加签，公钥解签，公钥加密，私钥解密的模式，如果使用的其他模式===== 暂不支持
	  var _rsahelper = new RSAHelper(RSAType.RSA, Encoding.UTF8, privateKey, publicKey, PrivateKeyType.PKCS8);

	  对接java常用实例化对象方式：           
	  RSAHelper rsaHelper = new RSAHelper(RSAType.RSA2, new UTF8Encoding(), privatekey, publickey,
                PrivateKeyType.PKCS8);
	  公钥和私钥的传递支持base64公钥私钥
	  如果遇到不同的算法，指定不同RSAType,和PrivateKeyType即可
	  
	  如果仅使用验签，加密的话，实例化对象的时候私钥传递空就是了
	  

	  var res = _rsahelper.Sign("test"); --加签 (返回的是加签之后的base64字符串)
	  var vres = _rsahelper.Verify(content, res); --验签 （content为验签内容，res为签名base64字符串）


	  -- 待加密字符串的长度最大为公钥长度-11，
	  -- RSA加密算法适用于较短的数据块，对于超长的字符串，建议使用对称加密算法，比如AES
	  -- 加解密需要指定加密方式（一般需要和对接方确认好加解密方式，与JAVA对接，java中默认的加解密方式是RSAEncryptionPadding.Pkcs1）
	  var eres = _rsahelper.Encrypt("test",RSAEncryptionPadding.Pkcs1); --加密 (加密自适应待加密字符串长度，不用担心超长) 

	  var dres =  _rsahelper.Decrypt(eres,RSAEncryptionPadding.Pkcs1); --解密 （eres为加密后的base64字符串）




 ~~~~
 ### 加解密方式
~~~~
1：PKCS #1 v1.5 PKCS #1 v1.5是RSA加密最早的填充方案之一。它使用了简单的填充方式，在加密和解密过程中都容易实现。然而，由于存在一些安全漏洞，不建议在新的应用中使用PKCS #1 v1.5填充。

2：OAEP-SHA1 OAEP（Optimal Asymmetric Encryption Padding）是一种更安全和更现代的填充方案。OAEP-SHA1使用SHA1作为哈希算法，用于在加密和解密过程中填充和解除填充的数据。SHA1是一种较旧的哈希算法，尽管在过去广泛使用，但现在不再被推荐用于安全性要求较高的应用。

3：OAEP-SHA512 OAEP-SHA512使用SHA512作为哈希算法，提供更高的安全性。SHA512是SHA-2系列中的一个算法，具有更长的摘要长度和更高的抗碰撞性能。它在安全性方面比SHA1更强大。

4：OAEP-SHA256 OAEP-SHA256使用SHA256作为哈希算法，也是SHA-2系列中的一种算法。SHA256是目前广泛使用的哈希算法之一，具有良好的安全性和性能。

  总的来说，PKCS #1 v1.5填充已经过时且不安全，应该避免使用。而OAEP填充提供更好的安全性和性能，其中OAEP-SHA512提供了最高级别的安全性，而OAEP-SHA256提供了良好的安全性和性能平衡。在选择填充方案和哈希算法时，应根据具体的安全需求和系统性能来进行权衡和选择。

 ~~~~

 
****