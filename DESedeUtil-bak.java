
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
 
 
public class DESedeUtil {
	
	/**
	 * 密钥算法
	 */
	private static final String KEY_ALGORITHM = "DESede";
	
	/**
	 * 加密/解密算法 / 工作模式 / 填充方式
	 * Java 6支持PKCS5Padding填充方式
	 * Bouncy Castle支持PKCS7Padding填充方式
	 */
	private static final String CIPHER_ALGORITHM = "DESede/ECB/PKCS5Padding";
	
	
	
	
	/**
	 * @Description: 生成密钥, 返回168位的密钥
	 * @return
	 * @throws Exception
	 */
	public static String generateKey() throws Exception {
		//实例化密钥生成器
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		//DESede 要求密钥长度为 112位或168位
		kg.init(168);
		//生成密钥
		SecretKey secretKey = kg.generateKey();
		//获得密钥的字符串形式
		return Base64.encodeBase64String(secretKey.getEncoded());
	}
	
	
	
	/**
	 * @Description: DES进行加密
	 * @param source 待加密的原字符串
	 * @param key  加密时使用的 密钥
	 * @return   返回经过base64编码的字符串
	 * @throws Exception
	 */
    public static String encrypt(String source, String key) throws Exception {
        byte[] sourceBytes = source.getBytes("UTF-8");
    	byte[] keyBytes = Base64.decodeBase64(key);
    	Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
    	cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(keyBytes, KEY_ALGORITHM));
    	byte[] decrypted = cipher.doFinal(sourceBytes);
    	return Base64.encodeBase64String(decrypted);
    }
    
    
    
    /**
     * @Description:  DES解密
     * @param encryptStr  DES加密后的再经过base64编码的密文
     * @param key  加密使用的密钥
     * @return  返回 utf-8 编码的明文
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
    
    
    
    // test
    public static void main(String[] args) {
    	try {
    		// 生成秘钥
        	String key = generateKey();
        	System.out.println("秘钥："+key);
        	
        	// 加密
        	String encryptStr = encrypt("hello", key);
        	System.out.println("密文："+ encryptStr);
        	// 解密
        	String resource = decrypt(encryptStr, key);
        	System.out.println("明文："+ resource);
        	
        	System.out.println("校验："+ "hello".equals(resource));
        	
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
    
}