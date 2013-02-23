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
import com.scs.security.misc.InvalidHmacException;

public class Crypto {
	
	private static final String ENC_ALGO 		= "AES/CBC/PKCS5Padding";
	private static final String KEY_FORMAT 		= "AES";
	private static final int 	KEY_SIZE 		= 32;
	
	protected static final String HMAC_ALGO 	= "HmacSHA256";
	
	public static final String KEY_EXPN_MSG		= "Invalid key format for \"%s\" algorithm!";
	public static final String ALGO_EXPN_MSG	= "Algorithm \"%s\" not found!";
	public static final String CONF_EXPN_MSG	= "Incorrect configuration for \"%s\" algorithm!";
	public static final String IV_EXPN_MSG		= "Invalid IV for \"%s\" algorithm!";
	public static final String BAD_HMAC_MSG		= "Wrong password or history file corrupted!";
    
    /**
     * Encrypts given byte data with the given key. Adds the encryption IV 
     * and HMAC over encrypted data as well.
     * @param data contents to be encrypted
     * @param hpwd key with which to encrypt (hardened password)
     * @return Encrypted data
     * @throws CryptoException if encryption fails for any reason.
     */
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
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (NoSuchPaddingException e) {
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (InvalidKeyException e) {
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		} catch (BadPaddingException e) {
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		}
    	
    	int offset = 0;
    	if ((iv = cipher.getIV()) == null) {
    		throw new CryptoException(String.format(IV_EXPN_MSG, ENC_ALGO));
    	}
    	byte[] ivLen = ByteBuffer.allocate(4).putInt(iv.length).array();
    	byte[] encLen = ByteBuffer.allocate(4).putInt(encData.length).array();
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
    
	/**
	 * Decrypts the provided data. Strips out the encryption IV and uses it 
	 * for decryption. Also compares the HMAC in the data with an HMAC calculated
	 * over the encrypted data to verify data integrity and key correctness.
	 * @param data contents to be decrypted
	 * @param hpwd key with which to decrypt (calculated hardened password)
	 * @return decrypted data
	 * @throws CryptoException if decryption fails for any reason.
	 * @throws InvalidHmacException if HMAC doesn't verify.
	 */
    public static byte[] decrypt(byte[] data, BigInteger hpwd) throws CryptoException, InvalidHmacException {
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
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (NoSuchPaddingException e) {
			throw new CryptoException(String.format(ALGO_EXPN_MSG, ENC_ALGO));
		} catch (InvalidKeyException e) {
			throw new CryptoException(String.format(KEY_EXPN_MSG, ENC_ALGO));
		} catch (InvalidAlgorithmParameterException e) {
			throw new CryptoException(String.format(IV_EXPN_MSG, ENC_ALGO));
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		} catch (BadPaddingException e) {
			throw new CryptoException(String.format(CONF_EXPN_MSG, ENC_ALGO));
		}
    	
    	offset += encLen;
    	byte[] computedHmac = null;
    	byte[] readHmac = new byte[data.length - offset];
    	
    	System.arraycopy(data, offset, readHmac, 0, readHmac.length);
    	computedHmac = getHmac(encData, hpwd);
    	if (!Arrays.equals(computedHmac, readHmac)) {
    		throw new InvalidHmacException(BAD_HMAC_MSG);
    	}
    	
    	return decData;
    }
    
    /**
     * Computes the HMAC over the provided data.
     * @param data contents to be HMACed
     * @param key key to use to HMAC
     * @return HMAC of the data
     * @throws CryptoException if HMAC fails for any reason.
     */
    private static byte[] getHmac(byte[] data, BigInteger key) throws CryptoException {
    	try {
			Mac sha256_HMAC = Mac.getInstance(HMAC_ALGO);
			sha256_HMAC.init(new SecretKeySpec(Crypto.getKeyBytes(key, KEY_SIZE), HMAC_ALGO));
			return sha256_HMAC.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(String.format(ALGO_EXPN_MSG, HMAC_ALGO));
		} catch (InvalidKeyException e) {
			throw new CryptoException(String.format(KEY_EXPN_MSG, HMAC_ALGO));
		}
    }
    
    /**
     * Builds a byte array to be used as the key out of a BigInteger.
     * Pads or trims the BigInteger's byte representation to match the
     * provided key size.
     * @param bi the input BigInteger
     * @param keySize number of bytes in the result
     * @return the byte array of specified length.
     */
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
    	BigInteger key = new BigInteger("25366482378280858928741501701207693372647019406703867885089035669716333033678");
    	String plaintext = "Hello AES World!";
    	
    	System.out.println("Key: " + key);
    	System.out.println("Plaintext: " + plaintext);
    	
    	byte[] enc = encrypt(plaintext.getBytes(), key);
    	printByteArray("Ciphertext", enc);
    	
    	byte[] dec;
		try {
			dec = decrypt(enc, key);
	    	printByteArray("Decryption", dec);
	    	System.out.println("Plaintext: " + new String(dec));
		} catch (CryptoException | InvalidHmacException e) {
			System.out.println("Wrong key!");
		}
    }
    
    public static void printByteArray(String label, byte[] array) {
    	System.out.print(label + ": ");
    	for (int i = 0; i < array.length; i++) {
    		System.out.printf("%02X ", array[i]);
    	}
    	System.out.println();
    }
}