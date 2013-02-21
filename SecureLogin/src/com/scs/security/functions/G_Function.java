package com.scs.security.functions;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.scs.security.misc.CryptoException;

/**
 * Builds the function mapping for G<sub>r,pwd<sub>a</sub></sub>(&middot;).
 * <br/>
 * It is implemented as HMAC-SHA256<sub>r &oplus; SHA256(pwd<sub>a</sub>)</sub>(&middot;) mod q.
 * <br/>
 * The output is guaranteed to be positive.
 */
public class G_Function extends KeyedHashFunction {
	
	public G_Function(BigInteger r, String pwd_a, BigInteger q) throws CryptoException {
		this.q = q;
		
		try {
			sha256_HMAC = Mac.getInstance(HMAC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, HMAC_ALGO));
		}
		
		BigInteger pwdH = hashPwd(pwd_a);
		initHmac(r, pwdH);
	}
	
	private BigInteger hashPwd(String pwd_a) throws CryptoException {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(MD_ALGO);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(ALGO_EXPN_MSG, MD_ALGO));
		}
		
		byte[] pwdHash = md.digest(pwd_a.getBytes());
		return new BigInteger(pwdHash);
	}
	
	private void initHmac(BigInteger r, BigInteger pwd) throws CryptoException {
		BigInteger hmac_key = r.xor(pwd);
		try {
			sha256_HMAC.init(new SecretKeySpec(hmac_key.toByteArray(), HMAC_ALGO));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, HMAC_ALGO));
		}
	}
}