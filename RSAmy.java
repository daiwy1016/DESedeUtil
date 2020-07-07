import NdSecret.nd.secret.util.RSA;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.Key;
import java.math.*;
import java.security.*;

public class RSAmy
{  
  public static void main(String[] args) throws Exception {
    Hexmy myhex = new Hexmy();
    KeyFactory localObject6 = KeyFactory.getInstance("RSA", "BC");
    RSAPublicKeySpec localObject1 = new RSAPublicKeySpec(new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16), new BigInteger("11", 16));
    PublicKey localObject2 = ((KeyFactory)localObject6).generatePublic((RSAPublicKeySpec)localObject1);
    System.out.println(myhex.byte2hex(localObject2.getEncoded()));



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


      // KeyPair kp = RSA.generateKeyPair();
      // System.out.println(myhex.byte2hex(kp.getPublic().getEncoded()));
      // System.out.println(myhex.byte2hex(kp.getPrivate().getEncoded()));


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
    paramArrayOfByte = RSA.encrypt(getRsaPubKey(), paramArrayOfByte);
    if (paramArrayOfByte == null) {
      return null;
    }
    Hexmy myhex = new Hexmy();
    return myhex.byte2hex(paramArrayOfByte);
  }
  public static RSAPrivateKey getRsaPrivateKey()
  {
    return RSA.generateRSAPrivateKey("B38B9F5D42DEF0BDEF067D3009B1E92475E130399C9DC7CC31F0361D6581D0245CB3AE5664D9337D9370C5CC842D9362F4F51A259DDF928080457A40E682A2BB", "");
  }

  public static RSAPublicKey getRsaPubKey()
  {
    return RSA.generateRSAPublicKeyHex("bd909c8a4a1a19dd74543b2376383d13531a57424370ba027a0f30b3ed2da4518eff2a155541cee0b077e8a54910e11e71102b6ea2403d22df907334f0557fa3", "10001");
  }

}
