package com.test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.utils.FileUtils;
import com.utils.RSAUtils;

public class TestRsa {
	static String publicKey;
	static String privateKey;

	// 将Base64编码后的公钥转换成PublicKey对象
	public static PublicKey string2PublicKey(String pubStr) throws Exception {
		byte[] keyBytes = base642Byte(pubStr);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	// 将Base64编码后的私钥转换成PrivateKey对象
	public static PrivateKey string2PrivateKey(String priStr) throws Exception {
		byte[] keyBytes = base642Byte(priStr);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

	// 字节数组转Base64编码
	public static String byte2Base64(byte[] bytes) {
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(bytes);
	}

	// Base64编码转字节数组
	public static byte[] base642Byte(String base64Key) throws IOException {
		BASE64Decoder decoder = new BASE64Decoder();
		return decoder.decodeBuffer(base64Key);
	}

	// 获取公钥(Base64编码)
	public static String getPublicKey(PublicKey publicKey) {
		byte[] bytes = publicKey.getEncoded();
		return byte2Base64(bytes);
	}

	// 获取私钥(Base64编码)
	public static String getPrivateKey(PrivateKey privateKey) {
		byte[] bytes = privateKey.getEncoded();
		return byte2Base64(bytes);
	}

	// web端生成的密钥对可以是再java服务器端进行加密解密使用
	static String[] passwords = new String[] { "123456", "abcdef", "123abc",
			"!@#$%^&*()_+{}|:<>?", "！@#￥%……&*（）——+|“：？》《" };

	public static void pubKeyEncodeBatchTest(String pub, String pri)
			throws IOException {
		String pubFile = "d:/data/rsa/pubkey.txt";
		String priFile = "d:/data/rsa/prikey.txt";
		String PRIVATEKEY = FileUtils.read(priFile);
		String PUBLICKEY = FileUtils.read(pubFile);
		if (pub != null) {
			PUBLICKEY = pub;
			PRIVATEKEY = pri;
		} else {
			PRIVATEKEY = FileUtils.read(priFile);
			PUBLICKEY = FileUtils.read(pubFile);
			System.out.println("读文件pubkey：" + PUBLICKEY);
		}
		for (int i = 0; i < passwords.length; i++) {
			String finalString = RSAUtils.encryptedDataOnJava(passwords[i],
					PUBLICKEY);
			System.out.println("password=[" + passwords[i]
					+ "]\tencodeString=[" + finalString + "]");
			String res = RSAUtils.decryptDataOnJava(finalString, PRIVATEKEY);
			System.out.println("-----" + res + "-----------");
		}
	}

	public static void pubKeyEncodeBatch() throws Exception {
		Map<String, Object> pp = RSAUtils.genKeyPair();
		publicKey = getPublicKey((RSAPublicKey) pp.get(RSAUtils.PUBLIC_KEY));
		privateKey = getPrivateKey((RSAPrivateKey) pp
				.get(RSAUtils.PRIVATE_KEY));
		System.err.println("新公钥: \n\r" + publicKey);
		System.err.println("新私钥： \n\r" + privateKey);
		pubKeyEncodeBatchTest(publicKey, privateKey);

	}

	/**
	 * 服务端生成的公钥，第三方网站进行加密为string,string由后端服务器解密。
	 * 
	 * @throws IOException
	 */
	public static void decode(String pri, String data) throws IOException {
		BASE64Decoder de = new BASE64Decoder();
		String aaa = new String(de.decodeBuffer(data));
		// System.out.println("aaa:"+aaa);
		System.out.println("解密数据：" + RSAUtils.decryptDataOnJava(data, pri));
		String res = RSAUtils.decryptDataOnJava(data, pri);
		System.out.println(res);
	}

	public static void main(String[] args) throws Exception {
		pubKeyEncodeBatch();

		Map<String, Object> keyMap = RSAUtils.genKeyPair();
		/*
		 * publicKey = RSAUtils.getPublicKey(keyMap); privateKey =
		 * RSAUtils.getPrivateKey(keyMap);
		 */

		publicKey = getPublicKey((RSAPublicKey) keyMap.get(RSAUtils.PUBLIC_KEY));
		privateKey = getPrivateKey((RSAPrivateKey) keyMap
				.get(RSAUtils.PRIVATE_KEY));
		System.err.println("新公钥: \n\r" + publicKey);
		System.err.println("新私钥： \n\r" + privateKey);
		String data = "";
		String PRIVATEKEY = "";
		/*
		 * String PRIVATEKEY =
		 * "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAj3hZfehWrrwTIRrfdKSDDFp1E5PPWW+xdEAQwWGEtWLrpeU9zm1SIo5w4azPf0JF54q0LcqGDFlLeqHKMJe7OwIDAQABAkB2fw9jN6/ImFwwXpKrM2ltnZTPO6jplJ/7hSKRpirG6JSfNOQGV4JyinzoarDx6jSYwpAv7DMmC6ccxIfq6bqBAiEAzZdRjGCs6Fe3gh+s/Ck+a6KZhUI9Nvnqd4Bvl8lFakECIQCypceOGA00ygubaBSP+yvUAy2v8kyP/e1Pvq613aYuewIgMOwAGMJsgsFUxp8Y/8wksWI42+/+NxXTSGqEo37eiMECIF5ZV48f/LmIi6DD0zhHeto544MtAGp7vT2Eg1jhesbJAiEAk2iVqqG/NN071k78bN8dfYqP13V9bMF4ip28ZXIRKMg="
		 * ; String data =
		 * "EaoAxGMKNgXddoPocq81Ktq9InNDuVz3TZdfVARDF9H0IxJKJSBSB2ZrKRDnm8EkpVjJ5jZmtrt1+/kUdKCL"
		 * ;data=
		 * "KCuJr8Kl7gZTJ3Bo/Yo7J3Ci/MUw/sc7coitZ/LU2ohLHYrKq4Uwlrg1uhtZr9cDpJS7f810wNMe+qsjxx8sCg=="
		 * ;
		 */

		/*
		 * "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhSzPPnFn41iaz+t4tI4kbaXNu"+
		 * "NFOsI8hFeCYtlwPFKRbETHbBS10bMvUbOWLFtRgZV3L924GQ9orbomEmJ1nWyaSO"+
		 * "8iBbZAyiWUP5PJJh/b9kHj1MMwG712bGfYYPdjkRprNpzU9w4UBzUMKKUoHU4c/G"+
		 * "bb4XeBK9LNTPWQL4YwIDAQAB";
		 */

		/*
		 * PRIVATEKEY=
		 * "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAOFLM8+cWfjWJrP6"+
		 * "3i0jiRtpc240U6wjyEV4Ji2XA8UpFsRMdsFLXRsy9Rs5YsW1GBlXcv3bgZD2itui"+
		 * "YSYnWdbJpI7yIFtkDKJZQ/k8kmH9v2QePUwzAbvXZsZ9hg92ORGms2nNT3DhQHNQ"+
		 * "wopSgdThz8Ztvhd4Er0s1M9ZAvhjAgMBAAECgYEAxwNLTUXsJGfn4Gzm/jC52MEZ"+
		 * "+mu2zgT90IAGGZeg+PUG63gwHyeXo4MsCVRz7/m8xAX/ykew+IEQwFt8Pdvc+rrs"+
		 * "5yml4gOBPfhpau5QaI75xNjnyH7UA3mbRCZeyZrvuKqtY/f8pCgzy3EBWnRpkcsq"+
		 * "eE6bsOQrD45mltr+0QECQQDynvhKEh+hD5xBpF/DIP8Fp6fizexHdA6+aZT/gLaF"+
		 * "A4XgZ9HEDDBhvNdadyYUNOLWhkxRHv6CkT5azfLXsJEhAkEA7begtbBCDXDf1+DR"+
		 * "h3j2S8zcv6+utYgcpjvxZqjbPi6UIWXLxI80PIwQ0uouHCUMjikBA6VX9vTbw9TZ"+
		 * "/IelAwJBAKI3W7baiz86mrTg3A4w/5GeWQexuurDVCBHo5F5U493nYk+oOe9ZpPS"+
		 * "mQIpa9JS0d+xB1GtsWlHBzPbQySnL0ECQA/btCjqvT1QTl6EbPXwp92eqQtQmQMb"+
		 * "NW4RiaUjlpyrVs5zkAho1T9EyMqJPNI71n6VVa/8k8WxyAdkZ7ZlBikCQEkNe1+s"+
		 * "AKnh+AFGCJ+6WAq1J2RuIgcA6bVL3ip7F2NHdE+N+tR9JqWw3JNCweWmAlzKIGs6"+
		 * "eKSVD5egzKaLXss=";
		 */

		/*
		 * String priFile="d:/data/rsa/prikey.txt";
		 * 
		 * PRIVATEKEY = FileUtils.read(priFile);
		 * System.out.println("读文件prikey："+PRIVATEKEY);
		 */
		// 服务端生成
		PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALE7dRg4kvesRQQvcEDWApH65gKArD6XXchl9DXlcedGU+3BIg5U3XwKTUyngLf8Y+ttoPhyC1QxCgJKPs5QGvwqxdN9h8vvis7QB7/kgpGH2VmD2pXwNMKjqYrZhT3T275ZnnZilFbyAFVEHdXHKy7LV0P0HcAUgx6Rzq0RPaJRAgMBAAECgYA2p3E6oOehfPxjiAWD2Ps97TNU/j0fqCoBjH88x57ShTuIjBBmfwE2KS8hPl5RXoGprkr/kpuvwNenUSIBGW7YZRcIOEKVLI2puWg6l0DJwx4QjPuTkX11pyWmXl/zDh0reSzmSHQWHAL1BOcPbrmJm1Y1DWAnqk9DbHapjanLKQJBAN197lgJiVbYQHTnUOkCZ14oMrfrchTsfgq0OiEnc+SdoEl5d8647taVelOaPjUSBPGkYHzZj9gWKFx7v8V3uSMCQQDM2EHGyNnAAVdeHd/0CPSVKTaq8pqVX28gJjdPU913W/3O+xLT3xKt/IM8KQtMkcy8pJ7d4QsXLEMZtXNb/r/7AkEAyKnEe0H4iRNWIhNG/DLPT0B/4pyOOGKhNjVdzJefqWkcxDQl1MU6rHGz53YAEbiHfhx7xeCdLxmz60W50b7LnQJBAKJ6DYIsoXqIFdJTA+W+jLEbJX9mOnKsZaosZcaIEKuxzZk00HQ5Bcn29ejr7UhohOpD8Law32kb9IUZxUx8va0CQHszx/A+aK0e72jJf7kCg/WUcf9EjQhvY9irqSDqYWN4QkViM5VaFIjZr9WXT0GTKMTUWLkGm2YdqrPfaYmuTdM=";
		// 123
		// data =
		// "nChIhG7Gr/+3QHBZ63kVW5Tqn2abnKEQX0EuzkLt5mmi7sriTMxE30YARupPbd0jW2suQfEVvR+Z78u5LUPGTsp5qH6DPMFkwZ/XtWLAvp2Y9cRUsbiIcj42vQPbSEA5J9DClOxOriy4KR8qO6OcHRn59gVnlYXOxrZ72kHTX6A=";
		// data =
		// "e/bGry0f5kttDOslkBf0JiS/MTYDXkR+q8pMqRWota+JDfXpXOQmdbYwRHmIIqeUuSIDiWJuPVba9PurPIbb174qIYcZisr6rLINlZTPMGlo4gSEREez+/BSiU5SP35k3xETHmh8NSC4TX6wzJwewhsfh+guyR35b4QX4aep5zQ=";
		// web端加密
		data = "lEVyjdceCw2+PEFt0xwgLEI+dBG/btyIwCIEmUtZopOJII6yHuSQC5N69UT0DK7nz/EiNKnRkpylNq5ixTQUXGOD0nVmp7rzP/+aG8e4XNTVkpD6gSecmRr68SJtZ4bdHHunM13HDfeOrupRvZHxFijwdUxaHN0O+Oho1AFV90A=";
		// pkcs1_padding生成 utf8编码
		/*
		 * BASE64Decoder de = new BASE64Decoder(); String aaa = new
		 * String(de.decodeBuffer(data)); System.out.println("aaa:"+aaa);
		 * System.out.println("解密数据：" + RSAUtils.decryptDataOnJava(data,
		 * PRIVATEKEY)); String res = RSAUtils.decryptDataOnJava(data,
		 * PRIVATEKEY); System.out.println(res);
		 */
		decode(PRIVATEKEY, data);
		String pub = getPublicKey((RSAPublicKey) keyMap
				.get(RSAUtils.PUBLIC_KEY));
		System.out.println("pub:" + pub);
		String pri = getPrivateKey((RSAPrivateKey) keyMap
				.get(RSAUtils.PRIVATE_KEY));
		System.out.println("pri:" + pri);
	}

	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, PublicKey key) {
		byte[] cipherText = null;
		try {
			// get an RSA cipher object and print the provider
			Security.addProvider(new BouncyCastleProvider());// org.bouncycastle.jce.provider.
			final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);
			// encrypt the plain text using the public key
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherText = cipher.doFinal(text.getBytes());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, PrivateKey key) {
		byte[] dectyptedText = null;
		try {
			// get an RSA cipher object and print the provider
			Security.addProvider(new BouncyCastleProvider());
			final Cipher cipher = Cipher.getInstance(PADDING, PROVIDER);

			// decrypt the text using the private key
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(text);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return new String(dectyptedText);
	}

	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold name of the encryption padding. RSA/ECB/PKCS1Padding
	 */
	public static final String PADDING = "RSA/ECB/OAEPPadding";// RSA/NONE/NoPadding
																// RSA/ECB/PKCS1Padding

	/**
	 * String to hold name of the security provider.
	 */
	public static final String PROVIDER = "BC";
}