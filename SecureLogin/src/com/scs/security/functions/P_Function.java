package com.scs.security.functions;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.scs.security.misc.CryptoException;

/**
 * Builds the function mapping for P<sub>r</sub>(&middot;).
 * <br/>
 * It is implemented as HMAC-SHA256<sub>r</sub>(&middot;) mod q.
 * <br/>
 * The output is guaranteed to be positive.
 */
public class P_Function extends KeyedHashFunction {

	public P_Function(BigInteger r, BigInteger q) throws CryptoException {
		this.q = q;
		
		try {
			sha256_HMAC = Mac.getInstance(HMAC_ALGO);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KeyedHashFunction.ALGO_EXPN_MSG, HMAC_ALGO));
		}
		
		initHmac(r);
	}

	private void initHmac(BigInteger r) throws CryptoException {
		try {
			sha256_HMAC.init(new SecretKeySpec(r.toByteArray(), HMAC_ALGO));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(String.format(KEY_EXPN_MSG, HMAC_ALGO));
		}
	}
}