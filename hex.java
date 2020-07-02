package org.it315.hex;
public class hex
{
  private static char[] hexChar = { 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102 };
  
  public static String byte2hex(byte[] paramArrayOfByte)
  {
    StringBuilder localStringBuilder = new StringBuilder(paramArrayOfByte.length * 2);
    for (int i = 0; i < paramArrayOfByte.length; i++)
    {
      localStringBuilder.append(hexChar[((paramArrayOfByte[i] & 0xF0) >>> 4)]);
      localStringBuilder.append(hexChar[(paramArrayOfByte[i] & 0xF)]);
    }
    return localStringBuilder.toString();
  }
  
  public static byte[] hex2byte(String paramString)
  {
    char[] arrayOfChar = paramString.toCharArray();
    byte[] arrayOfByte = new byte[paramString.length() / 2];
    int i = 0;
    int j = paramString.length();
    int m;
    for (int k = 0; k < j; k = m + 1)
    {
      //paramString = new StringBuilder().append("");
      m = k + 1;
      arrayOfByte[i] = new Integer(Integer.parseInt(arrayOfChar[k] + arrayOfChar[m], 16) & 0xFF).byteValue();
      i++;
    }
    return arrayOfByte;
  }

}
