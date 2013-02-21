package com.scs.security.functions;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.crypto.Mac;

import com.scs.security.Constants;
import com.scs.security.misc.CryptoException;

public class KeyedHashFunction {

	protected static final String MD_ALGO 			= "SHA-256";
	protected static final String HMAC_ALGO 		= "HmacSHA256";

	protected static final String KEY_EXPN_MSG		= "Invalid key format for \"%s\" algorithm!";
	protected static final String ALGO_EXPN_MSG		= "Algorithm \"%s\" not found!";
	
	protected static final int KEY_SIZE 			= 32;

	protected Mac sha256_HMAC;
	
	public BigInteger execute(int x) {
		byte[] input = ByteBuffer.allocate(4).putInt(x).array();
		byte[] result = sha256_HMAC.doFinal(input);
		return new BigInteger(result).mod(Constants.Q);
	}
	
	public static void main(String args[]) throws CryptoException {
		BigInteger r = new BigInteger("31087632152199639543726474312338815811421477996964447378948726738683786175667");
		String pwd = "dummy";
		
		System.out.println(r.bitCount() + "\t" + r.bitLength() + "\t" + r.toByteArray().length);
		
		KeyedHashFunction g = new G_Function(r, pwd);
		KeyedHashFunction p = new P_Function(r);
		
		System.out.println(g.execute(6));
		System.out.println(p.execute(6));
	}
}