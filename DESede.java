package NdSecret.nd.secret.util;

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

public class DESede
{
  private String algorithm = "DESede/CBC/PKCS7Padding";
  private String charset = "utf-8";
  private SecretKey key;
  private SecretKeyFactory keyFactory;
  private KeySpec keySpec;
  
  public DESede()
  {
    try
    {
      this.key = KeyGenerator.getInstance("DESede").generateKey();
      return;
    }
    catch (NoSuchAlgorithmException localNoSuchAlgorithmException)
    {
      for (;;)
      {
        localNoSuchAlgorithmException.printStackTrace();
      }
    }
  }
  
  public DESede(String paramString)
  {
    try
    {
      initKey(paramString.getBytes(this.charset));
      return;
    }
    catch (UnsupportedEncodingException paramString)
    {
      for (;;)
      {
        paramString.printStackTrace();
      }
    }
  }
  
  public DESede(byte[] paramArrayOfByte)
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
      DESedeKeySpec localDESedeKeySpec = new javax.crypto.spec.DESedeKeySpec();
      localDESedeKeySpec.init(updateKey(paramArrayOfByte));
      this.keySpec = localDESedeKeySpec;
      this.key = this.keyFactory.generateSecret(this.keySpec);
      return;
    }
    catch (InvalidKeyException paramArrayOfByte)
    {
      for (;;)
      {
        paramArrayOfByte.printStackTrace();
      }
    }
    catch (InvalidKeySpecException paramArrayOfByte)
    {
      for (;;)
      {
        paramArrayOfByte.printStackTrace();
      }
    }
    catch (NoSuchAlgorithmException paramArrayOfByte)
    {
      for (;;)
      {
        paramArrayOfByte.printStackTrace();
      }
    }
  }
  
  private byte[] updateKey(byte[] paramArrayOfByte)
  {
    int i = paramArrayOfByte.length;
    byte[] arrayOfByte1 = paramArrayOfByte;
    if (paramArrayOfByte.length < 24)
    {
      arrayOfByte1 = new byte[24];
      byte[] arrayOfByte2 = new byte[24 - i];
      for (int j = 0; j < 24 - i; j++) {
        arrayOfByte2[j] = ((byte)0);
      }
      System.arraycopy(paramArrayOfByte, 0, arrayOfByte1, 0, i);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte1, i, 24 - i);
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
   public static byte[] a(byte[] p1, byte[] p2)
   {
     Security.addProvider(new BouncyCastleProvider());
     SecretKeySpec localSecretKeySpec = new SecretKeySpec(p1, "AES");
     Cipher localCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
     localCipher.init(2, localSecretKeySpec, new IvParameterSpec(a));
     return localCipher.doFinal(p2);
   }
}
