package com.scs.security;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.scs.security.misc.CryptoException;

public class Crypto {
	
	private static final String ENC_ALGO 		= "AES/CBC/PKCS5Padding";
	private static final String KEY_FORMAT 		= "AES";
	private static final int 	KEY_SIZE 		= 32;
	
	protected static final String HMAC_ALGO 	= "HmacSHA256";
	
	public static final String KEY_EXPN_MSG		= "Invalid key format for \"%s\" algorithm!";
	public static final String ALGO_EXPN_MSG	= "Algorithm \"%s\" not found!";
	public static final String CONF_EXPN_MSG	= "Incorrect configuration for \"%s\" algorithm!";
	public static final String IV_EXPN_MSG		= "Invalid IV for \"%s\" algorithm!";
	public static final String BAD_HMAC_MSG		= "History file is probably corrupted!";
    
    @SuppressWarnings("unused")
	public static byte[] encrypt(byte[] data, BigInteger hpwd) throws CryptoException {
    	SecretKeySpec secret = new SecretKeySpec(getKeyBytes(hpwd, KEY_SIZE), KEY_FORMAT);
    	Cipher cipher = null;
    	byte[] encData = null;
    	byte[] hmac = null;
    	byte[] iv = null;
    	
    	try {
			cipher = Cipher.getInstance(ENC_ALGO);
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			encData = cipher.doFinal(data);
			hmac = getHmac(encData, hpwd);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		}
    	
    	int offset = 0;
    	iv = cipher.getIV();
    	byte[] ivLen = ByteBuffer.allocate(4).putInt(iv.length).array();
    	byte[] encLen = ByteBuffer.allocate(4).putInt(encData.length).array();
    	
    	if (iv == null) {
    		throw new CryptoException(String.format(IV_EXPN_MSG, ENC_ALGO));
    	}
    	
    	byte[] result = new byte[8 + iv.length + encData.length + hmac.length];
    	System.arraycopy(ivLen, 0, result, offset, 4);
    	offset += 4;
    	System.arraycopy(iv, 0, result, offset, iv.length);
    	offset += iv.length;
    	System.arraycopy(encLen, 0, result, offset, 4);
    	offset += 4;
    	System.arraycopy(encData, 0, result, offset, encData.length);
    	offset += encData.length;
    	System.arraycopy(hmac, 0, result, offset, hmac.length);
    	
    	return result;
    }
    
    public static byte[] decrypt(byte[] data, BigInteger hpwd) throws CryptoException {
    	SecretKeySpec secret = new SecretKeySpec(getKeyBytes(hpwd, KEY_SIZE), KEY_FORMAT);
    	Cipher cipher = null;
    	byte[] decData = null;
    	
    	int ivLen = ByteBuffer.wrap(data, 0, 4).getInt();
    	IvParameterSpec ivSpec = new IvParameterSpec(data, 4, ivLen);
    	int encLen = ByteBuffer.wrap(data, (4 + ivLen), 4).getInt();
    	int offset = ivLen + 8;
    	
    	byte[] encData = new byte[encLen];
    	System.arraycopy(data, offset, encData, 0, encLen);
    	
    	try {
			cipher = Cipher.getInstance(ENC_ALGO);
			cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
			decData = cipher.doFinal(encData);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(IV_EXPN_MSG, ENC_ALGO));
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		}
    	
    	offset += encLen;
    	byte[] computedHmac = null;
    	byte[] readHmac = new byte[data.length - offset];
    	
    	System.arraycopy(data, offset, readHmac, 0, readHmac.length);
    	computedHmac = getHmac(encData, hpwd);
    	if (!Arrays.equals(computedHmac, readHmac)) {
    		throw new CryptoException(BAD_HMAC_MSG);
    	}
    	
    	return decData;
    }
    
    private static byte[] getHmac(byte[] data, BigInteger key) throws CryptoException {
    	try {
			Mac sha256_HMAC = Mac.getInstance(HMAC_ALGO);
			sha256_HMAC.init(new SecretKeySpec(Crypto.getKeyBytes(key, KEY_SIZE), HMAC_ALGO));
			return sha256_HMAC.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, HMAC_ALGO));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, HMAC_ALGO));
		}
    }
    
    public static byte[] getKeyBytes(BigInteger bi, int keySize) {
    	byte[] key = new byte[keySize];
    	byte[] biBytes = bi.toByteArray();
    	if (biBytes.length >= keySize) {
    		System.arraycopy(biBytes, (biBytes.length - keySize), key, 0, keySize);
    	}
    	else {
    		System.arraycopy(biBytes, 0, key, (keySize - biBytes.length), biBytes.length);
    	}
    	return key;
    }
    
    public static void main(String args[]) throws CryptoException {
    	BigInteger key = new BigInteger("25366482378280858928741501701207693372647019406703867885089035669716333033679");
    	String plaintext = "Hello AES World!";
    	
    	System.out.println("Key: " + key);
    	System.out.println("Plaintext: " + plaintext);
    	
    	byte[] enc = encrypt(plaintext.getBytes(), key);
    	printByteArray("Ciphertext", enc);
    	
    	byte[] dec = decrypt(enc, key);
    	printByteArray("Decryption", dec);
    	
    	System.out.println("Plaintext: " + new String(dec));
    }
    
    private static void printByteArray(String label, byte[] array) {
    	System.out.print(label + ": ");
    	for (int i = 0; i < array.length; i++) {
    		System.out.printf("%02X ", array[i]);
    	}
    	System.out.println();
    }
}