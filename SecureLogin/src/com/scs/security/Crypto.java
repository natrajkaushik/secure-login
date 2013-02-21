package com.scs.security;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.scs.security.misc.CryptoException;

public class Crypto {
	
	private static final String ENC_ALGO = "AES/CBC/PKCS5Padding";
	private static final String KEY_FORMAT = "AES";
	private static final int KEY_SIZE = 32;
	
	public static final String KEY_EXPN_MSG		= "Invalid key format for \"%s\" algorithm!";
	public static final String ALGO_EXPN_MSG	= "Algorithm \"%s\" not found!";
	public static final String CONF_EXPN_MSG	= "Incorrect configuration for \"%s\" algorithm!";
    
    public static byte[] encrypt(byte[] data, BigInteger hpwd) throws CryptoException {
    	SecretKeySpec secret = new SecretKeySpec(getKeyBytes(hpwd, KEY_SIZE), KEY_FORMAT);
    	Cipher cipher = null;
    	byte[] encData = null;
    	
    	try {
			cipher = Cipher.getInstance(ENC_ALGO);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		}
    	try {
			cipher.init(Cipher.ENCRYPT_MODE, secret);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		}
    	try {
			encData = cipher.doFinal(data);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		}
    	
    	byte[] result = encData;
    	byte[] iv = cipher.getIV();
    	if (iv != null) {
    		result = new byte[iv.length + encData.length];
    		System.arraycopy(iv, 0, result, 0, iv.length);
    		System.arraycopy(encData, 0, result, iv.length, encData.length);
    	}
    	
    	return result;
    }
    
    public static byte[] decrypt(byte[] data, BigInteger hpwd) {
    	SecretKeySpec secret = new SecretKeySpec(getKeyBytes(hpwd, KEY_SIZE), KEY_FORMAT);
    	return null;
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
}