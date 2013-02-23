package com.scs.security;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

public class Generator {
	public static final int BIT_LENGTH = 256;
	public static final BigInteger LARGE_PRIME = getLargePrime(BIT_LENGTH);
	public static final BigInteger RANDOM_SEED = getRandomInteger(BIT_LENGTH);
	
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
	
	public static BigDecimal getRandomBigDecimal(){
		return new BigDecimal(getRandomInteger(BIT_LENGTH).mod(Constants.Q));
	}
	
	public static void main(String[] args){
		BigInteger hpwd = Generator.getHPWD(LARGE_PRIME);
		System.out.println(hpwd);
		System.out.println(Generator.LARGE_PRIME);
	}
}