import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import java.security.Security;  

public class DESmy
{
  private String algorithm = "DESede/CBC/PKCS7Padding";
  private String charset = "utf-8";
  private SecretKey key;
  private SecretKeyFactory keyFactory;
  private KeySpec keySpec;


  public static void main(String[] args) throws Exception {
    Security.addProvider(new com.sun.crypto.provider.SunJCE());  
    //Security.addProvider(new BouncyCastleProvider());
    //byte[] key = new DESmy().getKey();
    byte[] keytmp = hex2byte("3763326336383638313634323962623066633239616335623265633833653033");
    System.out.println(byte2Hex(keytmp));
    
    //byte[] key = Base64.decodeBase64("fCxoaBZCm7D8KaxbLsg+Aw==");
    System.out.println(Base64.encodeBase64String(keytmp));


    DESmy localObject = new DESmy();

    byte[] paramArrayOfByte = {49,50,51};
    byte[] en = ((DESmy)localObject).encrypt(paramArrayOfByte);
    System.out.println(en);
    System.out.println(byte2Hex(en));
    //System.out.println(Base64.encodeBase64String(en));
    //byte[] enen = en;
    //byte[] enen = Base64.decodeBase64("b78X/dli9XwZQ9bRAOtxONy/MOOEHu7OVLCDrmjwlAjMneFHhZy3BEd0eqvsWQNm3OiSva6rjJ3eaQcG4JBCBtPg7XQGI0jfSXH4FRMUWDrBkVBcA5WYm5/tS041frpJL+SCIFE1eEwXIBXsVbj2vdrbKbpD+eDn");
    byte[] enen = hex2byte("A2C9CB1671DEB1DC398C8B800430D5A177189FE7E3F52837A1F42C1FA1E19D85E0BCFE50AE34A2C527778D20267125E297322900402B986D987D8D080F76455289B4EF5328AD7229186C9E6919B09C8B69B4496CE609DFB4440B288D647B9B65351B1B9354F13562");
    System.out.println(byte2Hex(enen));
    System.out.println(enen);
    
    System.out.println("this.key");
    byte[] l = localObject.getKey();
    System.out.println(byte2Hex(l));

    byte[] de = ((DESmy)localObject).decrypt(enen);
    System.out.println(byte2Hex(de));
    //System.out.println(Base64.encodeBase64String(de));
    //System.out.println(de.toString().getBytes("utf-8"));
    
  }
  public static byte[] hex2byte(String paramString)
{

  if (paramString.length() % 2 == 0)
  {

    char[] arrayOfChar = paramString.toCharArray();
    byte[] arrayOfByte = new byte[paramString.length() / 2];
    int i = paramString.length();
    int j = 0;
    for (int k = 0; j < i; k++)
    {
      
      StringBuilder ps = new StringBuilder();
      ps.append("");
      int m = j + 1;
      ps.append(arrayOfChar[j]);
      ps.append(arrayOfChar[m]);
      arrayOfByte[k] = new Integer(Integer.parseInt(ps.toString(), 16) & 0xFF).byteValue();
      j = m + 1;
    }
    return arrayOfByte;
  }
  return new byte[0];
}




  //转换成十六进制字符串  
  public static String byte2Hex(byte[] b){  
    String hs="";  
    String stmp="";  
    for(int n=0; n<b.length; n++){  
    stmp = (java.lang.Integer.toHexString(b[n]& 0XFF));  
    if(stmp.length()==1){  
    hs = hs + "0" + stmp;  
    }else{  
    hs = hs + stmp;  
    }  
    if(n<b.length-1)hs=hs+" ";  
    }  
    return hs.toUpperCase();  
    }  

  public static void byteToHex(byte[] qKeyBytes){  
    for (int i = 0; i < qKeyBytes.length; i++) {
		String s = Integer.toHexString(qKeyBytes[i] & 0xFF);
		  if (s.length() == 1) {
        System.out.println("原始密钥=====" + i + "====" + "0" + s);
       
		   } else {
        System.out.println("原始密钥=====" + i + "====" + s);
      
			}
      } 
      return ;
} 

  public DESmy()
  {
    try
    {
      this.key = KeyGenerator.getInstance("DESede").generateKey();
    }
    catch (NoSuchAlgorithmException localNoSuchAlgorithmException)
    {
      localNoSuchAlgorithmException.printStackTrace();
    }
  }
  
  public DESmy(String paramString)
  {
    try
    {
      initKey(paramString.getBytes(this.charset));
    }
    catch (UnsupportedEncodingException paramStringex)
    {
      paramStringex.printStackTrace();
    }
  }
  
  public DESmy(byte[] paramArrayOfByte)
  {
    initKey(paramArrayOfByte);
  }
  
  private static IvParameterSpec IvGenerator(byte[] paramArrayOfByte)
  {
    byte[] arrayOfByte = new byte[8];
    System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, 8);
    return new IvParameterSpec(arrayOfByte);
  }
  
  private void initKey(byte[] paramArrayOfByte)
  {
    try
    {
      this.keyFactory = SecretKeyFactory.getInstance("DESede");
      DESedeKeySpec localDESedeKeySpec = new javax.crypto.spec.DESedeKeySpec(updateKey(paramArrayOfByte));
      //localDESedeKeySpec.init();
      this.keySpec = localDESedeKeySpec;
      this.key = this.keyFactory.generateSecret(this.keySpec);
    }
    catch (NoSuchAlgorithmException paramArrayOfByte1)
    {
      paramArrayOfByte1.printStackTrace();
    }
    catch (InvalidKeySpecException paramArrayOfByte2)
    {
      paramArrayOfByte2.printStackTrace();
    }
    catch (InvalidKeyException paramArrayOfByte3)
    {
      paramArrayOfByte3.printStackTrace();
    }
  }
  
  private byte[] updateKey(byte[] paramArrayOfByte)
  {
    System.out.println("updateKey:");
    System.out.println(byte2Hex(paramArrayOfByte));
    
    int i = paramArrayOfByte.length;
    byte[] arrayOfByte1 = paramArrayOfByte;
    if (paramArrayOfByte.length < 24)
    {
      arrayOfByte1 = new byte[24];
      int j = 24 - i;
      byte[] arrayOfByte2 = new byte[j];
      for (int k = 0; k < j; k++) {
        arrayOfByte2[k] = ((byte)0);
      }
      System.arraycopy(paramArrayOfByte, 0, arrayOfByte1, 0, i);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte1, i, j);
    }
    return arrayOfByte1;
  }
  
  public byte[] decrypt(byte[] paramArrayOfByte)
    throws Exception
  {
    System.out.println(byte2Hex(this.key.getEncoded()));
    IvParameterSpec localIvParameterSpec = IvGenerator(this.key.getEncoded());
    Cipher localCipher = Cipher.getInstance(this.algorithm);
    localCipher.init(2, this.key, localIvParameterSpec);
    return localCipher.doFinal(paramArrayOfByte);
  }
  
  public String decryptStr(byte[] paramArrayOfByte)
    throws Exception
  {
    return new String(decrypt(paramArrayOfByte), this.charset);
  }
  
  public byte[] encrypt(byte[] paramArrayOfByte)
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, Exception
  {
    IvParameterSpec localIvParameterSpec = IvGenerator(this.key.getEncoded());
    Cipher localCipher = Cipher.getInstance(this.algorithm);
    localCipher.init(1, this.key, localIvParameterSpec);
    return localCipher.doFinal(paramArrayOfByte);
  }
  
  public byte[] encryptStr(String paramString)
    throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, Exception
  {
    return encrypt(paramString.getBytes(this.charset));
  }
  
  public String getCharset()
  {
    return this.charset;
  }
  
  public byte[] getKey()
  {
    return this.key.getEncoded();
  }
  
  public void setCharset(String paramString)
  {
    this.charset = paramString;
  }
}
