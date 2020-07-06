public class Hexmy
{
  private static char[] hexChar = { 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102 };
  
  public static void main(String[] args) throws Exception {
    byte[] keytmp = hex2byte("3763326336383638313634323962623066633239616335623265633833653033");
    System.out.println(byte2hex(keytmp));
  }
   //转换成十六进制字符串  
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
    throws IllegalArgumentException
  {
    if (paramString.length() % 2 != 0) {
      throw new IllegalArgumentException();
    }
    char[] arrayOfChar = paramString.toCharArray();
    byte[] arrayOfByte = new byte[paramString.length() / 2];
    int i = 0;
    int j = paramString.length();
    int m;
    for (int k = 0; k < j; k = m + 1)
    {
      StringBuilder ps = new StringBuilder().append("");      
      m = k + 1;
      ps.append(arrayOfChar[k]);
      ps.append(arrayOfChar[m]);
      arrayOfByte[i] = new Integer(Integer.parseInt(ps.toString(), 16) & 0xFF).byteValue();
      i++;
    }
    return arrayOfByte;
  }
}
