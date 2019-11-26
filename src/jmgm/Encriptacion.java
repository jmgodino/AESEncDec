package jmgm;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encriptacion {

	private static final String ALFABETO_IV = "IVIV1234IVIV1234";
	private static final String PASSWORD = "abcd";
	private static final String ALGORITMO = "AES/CBC/PKCS5Padding";

	public static void main(String[] args)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException,
			BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		Encriptacion enc = new Encriptacion();
		SecretKey key = enc.loadKey();
		String mensaje = "1234567812345678";
		String encriptado = enc.encriptar(key, mensaje);
		System.out.println(encriptado.length());
		String desencriptado = enc.desEncriptar(key, encriptado);
		System.out.println(desencriptado);

	}

	public String encriptar(SecretKey key, String mensaje) throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cifrado = Cipher.getInstance(ALGORITMO);
		IvParameterSpec iv = getIV();
		cifrado.init(Cipher.ENCRYPT_MODE, key, iv);

		return Base64.getEncoder().encodeToString(cifrado.doFinal(mensaje.getBytes()));
	}

	public String desEncriptar(SecretKey key, String mensaje) throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cifrado = Cipher.getInstance(ALGORITMO);
		IvParameterSpec iv = getIV();
		cifrado.init(Cipher.DECRYPT_MODE, key, iv);

		return new String(cifrado.doFinal(Base64.getDecoder().decode(mensaje)));
	}

	public SecretKey loadKey() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(PASSWORD.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        return secretKeySpec;
	}

	public IvParameterSpec getIV() throws NoSuchAlgorithmException, NoSuchPaddingException {
		
		return new IvParameterSpec(ALFABETO_IV.getBytes());
	}

}
