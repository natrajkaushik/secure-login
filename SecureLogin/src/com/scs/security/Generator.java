package com.scs.security;

import java.math.BigInteger;
import java.util.Random;

/***
 * Contains functions that generate large numbers needed for the scheme
 *
 */
public class Generator {
	public static final int BIT_LENGTH = 256;
	public static BigInteger R = getR();
	public static final String ZERO = "0";
	
	/***
	 * @param bitLength
	 * @return large prime of specified bit length
	 */
	public static BigInteger getLargePrime(int bitLength){
		return BigInteger.probablePrime(bitLength, new Random());
	}
	
	/***
	 * @param bitLength
	 * @return random BigInteger of specified bit length
	 */
	public static BigInteger getRandomInteger(int bitLength){
		return (new BigInteger(bitLength, new Random()));
	}
	
	/*** 
	 * @param Q
	 * @return random hardened password < Q
	 */
	public static BigInteger getHPWD(BigInteger Q){
		return getRandomInteger(BIT_LENGTH).mod(Q);
	}
	
	/***
	 * 
	 * @return random large integer mod Q
	 */
	public static BigInteger getRandomBigInteger(){
		return getRandomInteger(BIT_LENGTH).mod(Constants.Q);
	}
	
	/***
	 * @return randomly generated R
	 */
	private static BigInteger getR(){
		BigInteger random;
		String retrieved = LoginHandler.getPreferences().get(Constants.PREF_R, ZERO);
		random = ZERO.equals(retrieved) ? getRandomInteger(BIT_LENGTH): new BigInteger(retrieved);
		return random;
	}
	
//	public static void main(String[] args){
//		BigInteger hpwd = Generator.getHPWD(Constants.Q);
//		System.out.println(hpwd);
//		System.out.println(Constants.Q);
//		System.out.println(R);
//	}
}