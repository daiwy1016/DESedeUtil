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

public class DESmy
{
  private String algorithm = "DESede/CBC/PKCS5Padding";
  private String charset = "utf-8";
  private SecretKey key;
  private SecretKeyFactory keyFactory;
  private KeySpec keySpec;


  public static void main(String[] args) throws Exception {
    
    byte[] key = new DESmy().getKey();
    System.out.println(Base64.encodeBase64String(key));


    Object localObject = new DESmy(key);
    byte[] paramArrayOfByte = {49,50,51};
    byte[] en = ((DESmy)localObject).encrypt(paramArrayOfByte);
    System.out.println(en);
    byteToHex(en);
    System.out.println(Base64.encodeBase64String(en));
    byte[] enen = Base64.decodeBase64("CYLbffJvyoo=");
    byte[] de = ((DESmy)localObject).decrypt(enen);
    System.out.println(Base64.encodeBase64String(de));
    System.out.println(de.toString().getBytes("utf-8"));
    
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
