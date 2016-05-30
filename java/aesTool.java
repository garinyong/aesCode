package test2;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class aesTool {

	public final static byte[] ENCRYPT_IV = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0 };

	/**
	 * 
	 * @Title: encryptByKey
	 * @Description: 用给定的key加密字符串
	 * @param text
	 * @param key
	 * @return String
	 * @throws
	 */
	public final static String encryptByKey(String text, String key) {
		try {
			key = convertTo16Key(key);
			byte[] cipher = key.getBytes();
			BufferedBlockCipher engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
			engine.init(true, new ParametersWithIV(new KeyParameter(cipher), ENCRYPT_IV));
			byte[] content = text.getBytes("utf-8");
			byte[] enc = new byte[engine.getOutputSize(content.length)];
			int size1 = engine.processBytes(content, 0, content.length, enc, 0);
			int size2 = engine.doFinal(enc, size1);
			byte[] encryptedContent = new byte[size1 + size2];
			System.arraycopy(enc, 0, encryptedContent, 0, encryptedContent.length);
			return Base64.encode(encryptedContent);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * 
	 * @Title: decrypt
	 * @Description: 解密字符串
	 * @param content
	 * @param encCipher
	 * @param encIV
	 * @return String
	 * @throws
	 */
	public final static String decrypt(String content, byte[] encCipher, byte[] encIV) {
		try {
			BufferedBlockCipher engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
			engine.init(false, new ParametersWithIV(new KeyParameter(encCipher), encIV));
			byte[] encryptedContent = Hex.decode(content.getBytes());
			byte[] dec = new byte[engine.getOutputSize(encryptedContent.length)];
			int size1 = engine.processBytes(encryptedContent, 0, encryptedContent.length, dec, 0);
			int size2 = engine.doFinal(dec, size1);
			byte[] decryptedContent = new byte[size1 + size2];
			System.arraycopy(dec, 0, decryptedContent, 0, decryptedContent.length);
			return new String(decryptedContent, "utf-8");
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 
	 * @Title: decrypt
	 * @Description: 解密字符串
	 * @param content
	 * @param encCipher
	 * @param encIV
	 * @return String
	 * @throws
	 */
	private final static String decrypt(byte[] content, byte[] encCipher, byte[] encIV) {
		try {
			BufferedBlockCipher engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
			engine.init(false, new ParametersWithIV(new KeyParameter(encCipher), encIV));
			byte[] encryptedContent = content;
			byte[] dec = new byte[engine.getOutputSize(encryptedContent.length)];
			int size1 = engine.processBytes(encryptedContent, 0, encryptedContent.length, dec, 0);
			int size2 = engine.doFinal(dec, size1);
			byte[] decryptedContent = new byte[size1 + size2];
			System.arraycopy(dec, 0, decryptedContent, 0, decryptedContent.length);
			return new String(decryptedContent, "utf-8");
		} catch (Exception e) {
			//e.printStackTrace();

			return "";
		}
	}

	/**
	 * 
	 * @Title: decryptByKey
	 * @Description: 用制定的key对字符串解密
	 * @param text
	 * @param key
	 * @return String
	 * @throws
	 */
	public final static String decryptByKey(String text, String key) {
		try {
			byte[] decoded = Base64.decode(text);
			key = convertTo16Key(key);
			return decrypt(decoded, key.getBytes(), ENCRYPT_IV);
		} catch (Exception e) {
			//e.printStackTrace();
		}
		return null;
	}

	/**
	 * 
	 * @Title: getHexString
	 * @Description: 把字节数组转换成十六进制字符串
	 * @param b
	 * @param @throws Exception
	 * @return String
	 * @throws
	 */
	public static String getHexString(byte[] b) throws Exception {
		String result = "";
		for (int i = 0; i < b.length; i++) {
			result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return result;
	}

	/**
	 * 
	 * @Title: convertTo16Key
	 * @Description: 把key转换成16位的字符串
	 * @param entryKey
	 * @return String
	 * @throws
	 */
	private static String convertTo16Key(String entryKey) {
		if (!(entryKey == null)) {
			if (entryKey.length() == 16) {
				return entryKey;
			}
			if (entryKey.length() > 16) {
				return entryKey.subSequence(0, 16).toString();
			}
			if (entryKey.length() < 16) {
				return convet2Substi16Byte(entryKey);
			}
		}
		return null;
	}

	/**
	 * 
	 * @Title: convet2Substi16Byte
	 * @Description: 把长度小于16位的字符串末尾补"0"到16位
	 * @param key
	 * @return String
	 * @throws
	 */
	private static String convet2Substi16Byte(String key) {
		StringBuffer keyBuffer = new StringBuffer(key);
		for (int i = 0; i < 16 - key.length(); i++) {
			keyBuffer.append("0");
		}
		return keyBuffer.toString();
	}
}
