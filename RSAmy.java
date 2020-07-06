import NdSecret.nd.secret.util.RSA;
import java.security.KeyPair;

public class RSAmy
{  
  public static void main(String[] args) throws Exception {
    Hexmy myhex = new Hexmy();
    byte[] keytmp = myhex.hex2byte("3763326336383638313634323962623066633239616335623265633833653033");
    System.out.println(myhex.byte2hex(keytmp));
    System.out.println(RSA.getCharset());
    //KeyPair rsaKeyPair = RSA.generateKeyPair();   
    //System.out.println(rsaKeyPair.getPublic());
    //System.out.println(rsaKeyPair.getPrivate());


    //public static final String RSA_MODEL_HEX = "B38B9F5D42DEF0BDEF067D3009B1E92475E130399C9DC7CC31F0361D6581D0245CB3AE5664D9337D9370C5CC842D9362F4F51A259DDF928080457A40E682A2BB";
    //public static final String RSA_PUBKEY_HEX = "10001";

    //RSA_MODEL_HEX = "bd909c8a4a1a19dd74543b2376383d13531a57424370ba027a0f30b3ed2da4518eff2a155541cee0b077e8a54910e11e71102b6ea2403d22df907334f0557fa3";
   

    System.out.println(RSA.generateRSAPublicKeyHex("B38B9F5D42DEF0BDEF067D3009B1E92475E130399C9DC7CC31F0361D6581D0245CB3AE5664D9337D9370C5CC842D9362F4F51A259DDF928080457A40E682A2BB", "10001"));



    /*
     System.out.println(rsaKeyPair.getModules());
        System.out.println(rsaKeyPair.getPublicKey());
        System.out.println(rsaKeyPair.getPrivateKey());*/

  }

}
