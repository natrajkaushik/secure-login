package com.scs.security;

import java.math.BigInteger;
import java.util.Random;

public class Generator {
	public static final int BIT_LENGTH = 256;
	public static BigInteger R = getR();
	public static final String ZERO = "0";
	
	/* returns a large prime of specified bit length */
	public static BigInteger getLargePrime(int bitLength){
		return BigInteger.probablePrime(bitLength, new Random());
	}
	
	/* return random BigInteger of specified bit length */
	public static BigInteger getRandomInteger(int bitLength){
		return (new BigInteger(bitLength, new Random()));
	}
	
	/* returns a random hardened password < LARGE_PRIME */
	public static BigInteger getHPWD(BigInteger Q){
		return getRandomInteger(BIT_LENGTH).mod(Q);
	}
	
	public static BigInteger getRandomBigInteger(){
		return getRandomInteger(BIT_LENGTH).mod(Constants.Q);
	}
	
	private static BigInteger getR(){
		BigInteger random;
		String retrieved = LoginHandler.getPreferences().get(Constants.PREF_R, ZERO);
		random = ZERO.equals(retrieved) ? getRandomInteger(BIT_LENGTH): new BigInteger(retrieved);
		return random;
	}
	
	public static void main(String[] args){
		BigInteger hpwd = Generator.getHPWD(Constants.Q);
		System.out.println(hpwd);
		System.out.println(Constants.Q);
		System.out.println(R);
	}
}