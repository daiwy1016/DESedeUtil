import NdSecret.nd.secret.util.RSA;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Key;
import java.math.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.*;
import java.io.*;


public class RSAmy
{  

  /**
	* 加密
	* @param key 加密的密钥
	* @param data 待加密的明文数据
	* @return 加密后的数据
	* @throws Exception
	*/
	public static byte[] encrypt_byte(Key key, byte[] data) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(Cipher.ENCRYPT_MODE, key);
			//获得加密块大小，如:加密前数据为128个byte，而key_size=1024 加密块大小为127 byte,加密后为128个byte;
			//因此共有2个加密块，第一个127 byte第二个为1个byte
			int blockSize = cipher.getBlockSize();
			int outputSize = cipher.getOutputSize(data.length);//获得加密块加密后块大小
			int leavedSize = data.length % blockSize;
			int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
			byte[] raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (data.length - i * blockSize > 0) {
				if (data.length - i * blockSize > blockSize)
				cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
				else
				cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
				//这里面doUpdate方法不可用，查看源代码后发现每次doUpdate后并没有什么实际动作除了把byte[]放到ByteArrayOutputStream中
				//，而最后doFinal的时候才将所有的byte[]进行加密，可是到了此时加密块大小很可能已经超出了OutputSize所以只好用dofinal方法。
				i++;
			}
			return raw;
		} catch (Exception e) {
		throw new Exception(e.getMessage());
		}
	}
  	/**
	* 解密
	* @param key 解密的密钥
	* @param raw 已经加密的数据
	* @return 解密后的明文
	* @throws Exception
	*/
	public static byte[] decrypt_byte(Key key, byte[] raw) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", new org.bouncycastle.jce.provider.BouncyCastleProvider());
			cipher.init(cipher.DECRYPT_MODE, key);
			int blockSize = cipher.getBlockSize();
			ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
			int j = 0;
			while (raw.length - j * blockSize > 0) {
				bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
				j++;
			}
			return bout.toByteArray();
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}
	


  public static byte[] encrypt_my(Key pk, byte[] paramArrayOfByte)
  {
    try
    {
      Cipher localCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      localCipher.init(1, pk);
      System.out.println(localCipher);
      int i = localCipher.getBlockSize();
      int j = localCipher.getOutputSize(paramArrayOfByte.length);
      int kk = 0;
      System.out.println(i);
      if (paramArrayOfByte.length % i != 0) {
         kk = paramArrayOfByte.length / i + 1;
      } else {
         kk= paramArrayOfByte.length / i;
      }
      int x = kk * j ;
      byte[] paramKey = new byte[x];
      for (int k = 0;; k++)
      {
        int m = paramArrayOfByte.length;
        int n = k * i;
        if (m - n <= 0) {
          break;
        }
        if (paramArrayOfByte.length - n > i) {
          localCipher.doFinal(paramArrayOfByte, n, i, paramKey, k * j);
        } else {
          localCipher.doFinal(paramArrayOfByte, n, paramArrayOfByte.length - n, paramKey, k * j);
        }
      }
      return paramKey;
    }
    catch (Exception paramKey)
    {
      paramKey.printStackTrace();
    }
    return null;
  }

  public static byte[] decrypt_my(Key pk, byte[] paramArrayOfByte)
  {
    try
    {
      Cipher localCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");//
      localCipher.init(2, pk);
      int i = localCipher.getBlockSize();
      ByteArrayOutputStream pkey = new java.io.ByteArrayOutputStream(64);
      for (int j = 0; paramArrayOfByte.length - j * i > 0; j++) {
        pkey.write(localCipher.doFinal(paramArrayOfByte, j * i, i));
      }
      byte[] paramKey = pkey.toByteArray();
      return paramKey;
    }
    catch (Exception paramKey)
    {
    
        paramKey.printStackTrace();
        paramKey = null;

    }
    return new byte[0];
  }
  public static void main(String[] args) throws Exception {
    Hexmy myhex = new Hexmy();
 /*   KeyFactory localObject6 = KeyFactory.getInstance("RSA", "BC");
    RSAPublicKeySpec localObject1 = new RSAPublicKeySpec(
      new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed", 16),
      new BigInteger("11", 16)
      );
    PublicKey localObject2 = localObject6.generatePublic((RSAPublicKeySpec)localObject1);
    
*/
//System.out.println(myhex.byte2hex(getRsaPrivateKey().getEncoded()));

KeyPair keyPair = NdSecret.nd.secret.util.RSA.generateKeyPair();
RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
byte[] pubModBytes = pubKey.getModulus().toByteArray();
System.out.println(myhex.byte2hex(pubModBytes));
//返回公钥公用指数(字节数组形式)
byte[] pubPubExpBytes = pubKey.getPublicExponent().toByteArray();
System.out.println(myhex.byte2hex(pubPubExpBytes));

RSAPrivateKey priKey = (RSAPrivateKey) keyPair.getPrivate();

byte[] priModBytes = priKey.getModulus().toByteArray();
System.out.println(myhex.byte2hex(priModBytes));
//返回私钥专用指数(字节数组形式)
byte[] priPriExpBytes = priKey.getPrivateExponent().toByteArray();
System.out.println(myhex.byte2hex(priPriExpBytes));



System.out.println(pubKey);
System.out.println(priKey);
System.out.println("=====1111=======");


RSAPublicKey mypubkey = NdSecret.nd.secret.util.RSA.generateRSAPublicKeyHex("815afc844ee0252febc27fa5b0f6d895f5c3693d0b0afaa5e405524a2ef0a417ee911d6d3551eb98108d12f5bfe7a26818c7ac33815abd5d3afa1f234f829315","10001");
System.out.println(mypubkey);
RSAPrivateKey myprikey = NdSecret.nd.secret.util.RSA.generateRSAPrivateKey("815afc844ee0252febc27fa5b0f6d895f5c3693d0b0afaa5e405524a2ef0a417ee911d6d3551eb98108d12f5bfe7a26818c7ac33815abd5d3afa1f234f829315","6576c707c90ecc5c906319d90fbc301b40912ce532da43cd07d49cbd8fa0363569d364664104fcb80a60f5975109ae46b0f2c2b27d6946f2a80de90ccbd91e01");
System.out.println(myprikey);
System.out.println("=====2222=======");


       
System.out.println("======生成完毕======");
String str = "董利伟";
byte[] mw = encrypt_byte(mypubkey,str.getBytes());
System.out.println(myhex.byte2hex(mw));

System.out.println(new String(decrypt_byte(myprikey, mw)));

    // String RsaModelHex = "df4babe2c26727e7a290c582de785032291ce061f274fc8e998c6e3e9cd3b5d137e3588cfa49c5003d630684f1ca1c3ccb7bf93c464b1d2802838bfe3ad970f1";
    // Key puKey = RSA.generateRSAPublicKeyHex(RsaModelHex, "10001");
    // System.out.println(myhex.byte2hex(puKey.getEncoded()));

    // Key priKey = RSA.generateRSAPrivateKey(RsaModelHex, "10001");
    // System.out.println(myhex.byte2hex(priKey.getEncoded()));
/*
    byte[] signKey = myhex.hex2byte("af9feb29c8ceb0a9dcec3b2dac5ebd2f3a8513e901295dad528901e2213a5469e88638e62f38496ca803e55f86f59df19eda198f92f76bc925e2c429d3495051");

    System.out.println(myhex.byte2hex(new BigInteger("af9feb29c8ceb0a9dcec3b2dac5ebd2f3a8513e901295dad528901e2213a5469e88638e62f38496ca803e55f86f59df19eda198f92f76bc925e2c429d3495051", 16).toByteArray()));

    byte[] byte_mingwen = RSA.decrypt(getRsaPubKey(),new BigInteger("af9feb29c8ceb0a9dcec3b2dac5ebd2f3a8513e901295dad528901e2213a5469e88638e62f38496ca803e55f86f59df19eda198f92f76bc925e2c429d3495051", 16).toByteArray());
    System.out.println(myhex.byte2hex(byte_mingwen));

*/

    //  String p = "31323334353637383940";
 
    //  byte[] pbyte = myhex.hex2byte(p);
    
    //System.out.println(myhex.byte2hex(getRsaPrivateKey().getEncoded()));


    //System.out.println(myhex.byte2hex(getRsaPubKey().getEncoded()));
    //System.out.println(RSA.encryptStr(getRsaPubKey(), "B38B9F5D42DEF0BDEF067D3009B1E9"));








    //byte[] keytmp = myhex.hex2byte("3763326336383638313634323962623066633239616335623265633833653033");
    //System.out.println(myhex.byte2hex(keytmp));
    //System.out.println(RSA.getCharset());
    // KeyPair rsaKeyPair = RSA.generateKeyPair();   

    //  public_key = rsaKeyPair.getPublic();
    //  private_key = rsaKeyPair.getPrivate() 

    // System.out.println("public_key");
    // System.out.println(public_key);
    // System.out.println("private_key");
    // System.out.println(private_key);

/*
       KeyPair kp = NdSecret.nd.secret.util.RSA.generateKeyPair();
       System.out.println(kp.getPublic());
       System.out.println(kp.getPrivate());
       System.out.println("============");
       System.out.println(myhex.byte2hex(kp.getPublic().getEncoded()));
       System.out.println(myhex.byte2hex(kp.getPrivate().getEncoded()));*/


    //public static final String RSA_MODEL_HEX = "B38B9F5D42DEF0BDEF067D3009B1E92475E130399C9DC7CC31F0361D6581D0245CB3AE5664D9337D9370C5CC842D9362F4F51A259DDF928080457A40E682A2BB";
    //public static final String RSA_PUBKEY_HEX = "10001";

    //RSA_MODEL_HEX = "bd909c8a4a1a19dd74543b2376383d13531a57424370ba027a0f30b3ed2da4518eff2a155541cee0b077e8a54910e11e71102b6ea2403d22df907334f0557fa3";
   

    //System.out.println(RSA.generateRSAPublicKeyHex("B38B9F5D42DEF0BDEF067D3009B1E92475E130399C9DC7CC31F0361D6581D0245CB3AE5664D9337D9370C5CC842D9362F4F51A259DDF928080457A40E682A2BB", "10001"));

    // KeyPairGenerator kpg = null;
    // kpg = KeyPairGenerator.getInstance("RSA");

    // kpg.initialize(1024);
    // KeyPair kp = kpg.generateKeyPair();
    // RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
    // RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) kp.getPrivate();
    // System.out.println(myhex.byte2hex(publicKey.getEncoded()));
    // System.out.println(myhex.byte2hex(privateKey.getEncoded()));

    /*
     System.out.println(rsaKeyPair.getModules());
        System.out.println(rsaKeyPair.getPublicKey());
        System.out.println(rsaKeyPair.getPrivateKey());*/

  }

  public static String getDAEncrypt(byte[] paramArrayOfByte)
  {
    if (paramArrayOfByte == null) {
      return null;
    }
    paramArrayOfByte = encrypt_my(getRsaPubKey(), paramArrayOfByte);
    if (paramArrayOfByte == null) {
      return null;
    }
    Hexmy myhex = new Hexmy();
    return myhex.byte2hex(paramArrayOfByte);
  }
  public static RSAPrivateKey getRsaPrivateKey()
  {
    return RSA.generateRSAPrivateKey("13E3082013A020100024100C69506FA2B733836786BD0070A8C8776647D8767964DA4F0F6503702842704D97DF0E19BB83D650CC33CC72C8E4B617F2DB270F3DEEAA3EA722C647A8C9C5E990203010001024020ECC09565F2DA951D6E32B5982828A5968FC18D893C2266D94FFF6EE95E56CD35AE6C47AB0CA0CB53B2509608DEE965A3E6A5EEB02FF11CD022CD3513968B01022100F53CAB9A227A566611D67DE8E3F033205CA2158DFCA40C52F2CC8480F1ACBB71022100CF4C2C0FD4B4E0C202BC760502666FB6497282C22416378B67D2E8B1EAF431A902207F42A9A645C80877D53FE27CED742383E2AE35D345CC779CBFE483CA4A1FA1F1022100BBB7DBD2BE28C9BB86A4C92F021C671F2865B4F93F9A8AD407C1DB0C7A9A857902205B6A58C28781641A4E4F3035B1C79C073E8FCB760B40876A2A0147A093D53154", "10001");
  }

  public static RSAPublicKey getRsaPubKey()
  {
/*
305c300d06092a864886f70d0101010500034b003048024100
8c6ee99811d1043f33a857207c74cffe2067814ec26647932c863ee5582e126d1dcae29f288e64122f1ab28bcb20d3a9bc52dc828357208d9e792a002de4dac9
0203010001

30820153020100300d06092a864886f70d01010105000482013d308201390201000241008c6ee99811d1043f33a857207c74cffe2067814ec26647932c863ee5582e126d1dcae29f288e64122f1ab28bcb20d3a9bc52dc828357208d9e792a002de4dac90203010001024061eaf3f59476a8ff6885783aae8cc479ed1e3e8b2c0124e6f9a4a13648c5d71234e933ce485f842e59bb5f5dccfbae8b280eb662a30b329837f2373ce3a78a01022100cdb383e43a3a710f29cc1601c4eb3259d86fa1820146a4b80c106d6226c84f73022100aec5c0a90673ca0f66f4a7df1bf01906fab0815bcb4f1b8bd50a2cefa00165d302207a012a8e3877274dbe15bd4bc95752e2f53ba8c8aa271355d259fff6c257f6bf02206c1bc1180cf8b4e5a01ef8746718b6b27d818f1314090416141aee3eefafcda702204d1d461ecc53c62416d5f3671d8dd1d38c5e1ac3230bb5b62c3c8802101eeb0a
*/
    return RSA.generateRSAPublicKeyHex("8c6ee99811d1043f33a857207c74cffe2067814ec26647932c863ee5582e126d1dcae29f288e64122f1ab28bcb20d3a9bc52dc828357208d9e792a002de4dac9", "10001");
  }

}
