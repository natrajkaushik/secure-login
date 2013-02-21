package com.scs.security.functions;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.crypto.Mac;

import com.scs.security.misc.CryptoException;

public class KeyedHashFunction {

	public static final String MD_ALGO 			= "SHA-256";
	public static final String HMAC_ALGO 		= "HmacSHA256";

	public static final String KEY_EXPN_MSG		= "Invalid key format for \"%s\" algorithm!";
	public static final String ALGO_EXPN_MSG	= "Algorithm \"%s\" not found!";

	protected Mac sha256_HMAC;
	protected BigInteger q;
	
	public BigInteger execute(int x) {
		byte[] input = ByteBuffer.allocate(4).putInt(x).array();
		byte[] result = sha256_HMAC.doFinal(input);
		return new BigInteger(result).mod(q);
	}
	
	public static void main(String args[]) throws CryptoException {
		BigInteger q = new BigInteger("76966961417457034317419215168369078972149330037145547079608806201639921649788");
		BigInteger r = new BigInteger("31087632152199639543726474312338815811421477996964447378948726738683786175667");
		String pwd = "dummy";
		
		KeyedHashFunction g = new G_Function(r, pwd, q);
		KeyedHashFunction p = new P_Function(r, q);
		
		System.out.println(g.execute(6));
		System.out.println(p.execute(6));
	}
}