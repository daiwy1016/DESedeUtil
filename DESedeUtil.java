
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
 
 
public class DESedeUtil {
	
	/**
	 * ��Կ�㷨
	 */
	private static final String KEY_ALGORITHM = "DESede";
	
	/**
	 * ����/�����㷨 / ����ģʽ / ��䷽ʽ
	 * Java 6֧��PKCS5Padding��䷽ʽ
	 * Bouncy Castle֧��PKCS7Padding��䷽ʽ
	 */
	private static final String CIPHER_ALGORITHM = "DESede/CBC/PKCS7Padding";//DESede/ECB/PKCS5Padding
	
	
	
	
	/**
	 * @Description: ������Կ, ����168λ����Կ
	 * @return
	 * @throws Exception
	 */
	public static String generateKey() throws Exception {
		//ʵ������Կ������
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		//DESede Ҫ����Կ����Ϊ 112λ��168λ
		//kg.init(168);
		//������Կ
		SecretKey secretKey = kg.generateKey();
		//�����Կ���ַ�����ʽ
		return Base64.encodeBase64String(secretKey.getEncoded());
	}
	
	
	
	/**
	 * @Description: DES���м���
	 * @param source �����ܵ�ԭ�ַ���
	 * @param key  ����ʱʹ�õ� ��Կ
	 * @return   ���ؾ���base64������ַ���
	 * @throws Exception
	 */
    public static String encrypt(String source, String key) throws Exception {
        byte[] sourceBytes = source.getBytes("UTF-8");
    	byte[] keyBytes = Base64.decodeBase64(key);
    	Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS7Padding");//Cipher.getInstance(CIPHER_ALGORITHM,"BC");
    	cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(keyBytes, KEY_ALGORITHM));
    	byte[] decrypted = cipher.doFinal(sourceBytes);
    	return Base64.encodeBase64String(decrypted);
    }
    
    
    
    /**
     * @Description:  DES����
     * @param encryptStr  DES���ܺ���پ���base64���������
     * @param key  ����ʹ�õ���Կ
     * @return  ���� utf-8 ���������
     * @throws Exception
     */
    public static String decrypt(String encryptStr, String key) throws Exception {
    	byte[] sourceBytes = Base64.decodeBase64(encryptStr);
		byte[] keyBytes = Base64.decodeBase64(key);
    	Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    	cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(keyBytes, KEY_ALGORITHM));
    	byte[] decoded = cipher.doFinal(sourceBytes);
    	return new String(decoded, "UTF-8");
    }
   
	
/** 
 * �ֽ�תʮ������ 
 * @param b ��Ҫ����ת����byte�ֽ� 
 * @return  ת�����Hex�ַ��� 
 */  
public static String byteToHex(byte b){  
    String hex = Integer.toHexString(b & 0xFF);  
    if(hex.length() < 2){  
        hex = "0" + hex;  
    }  
    return hex;  
} 
/** 
 * Hex�ַ���תbyte 
 * @param inHex ��ת����Hex�ַ��� 
 * @return  ת�����byte 
 */  
public static byte hexToByte(String inHex){  
	return (byte)Integer.parseInt(inHex,16);  
 }  
    
public static byte[] hexToByteArray(String inHex){  
    int hexlen = inHex.length();  
    byte[] result;  
    if (hexlen % 2 == 1){  
        //����  
        hexlen++;  
        result = new byte[(hexlen/2)];  
        inHex="0"+inHex;  
    }else {  
        //ż��  
        result = new byte[(hexlen/2)];  
    }  
    int j=0;  
    for (int i = 0; i < hexlen; i+=2){  
        result[j]=hexToByte(inHex.substring(i,i+2));  
        j++;  
    }  
    return result;   
}  
    
    // test
    public static void main(String[] args) {
    	try {
			//test
			byte[] de = hexToByteArray("7c2c686816429bb0fc29ac5b2ec83e03");
			byte b = 0x18;
			String hexde = byteToHex(de[0]);
			System.out.println(hexde);
			String s = Base64.encodeBase64String(de);
			System.out.println("��Կ��"+s);
    		// ������Կ
        	String key = generateKey();
        	System.out.println("��Կ��"+key);
        	
        	// ����
        	String encryptStr = encrypt("hello", key);
        	System.out.println("���ģ�"+ encryptStr);
        	// ����
        	String resource = decrypt(encryptStr, key);
        	System.out.println("���ģ�"+ resource);
        	
        	System.out.println("У�飺"+ "hello".equals(resource));
        	
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
    
}