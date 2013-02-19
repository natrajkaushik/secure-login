package com.scs.security;

import java.math.BigInteger;
import java.util.Random;

public class Generator {
	public static final int BIT_LENGTH = 160;
	public static final BigInteger LARGE_PRIME = getLargePrime(BIT_LENGTH);
	
	public static BigInteger getLargePrime(int bitLength){
		return BigInteger.probablePrime(bitLength, new Random());
	}
	
	public static BigInteger getRandomInteger(int bitLength){
		return (new BigInteger(bitLength, new Random()));
	}
	
	public static BigInteger getHPWD(){
		
		/* BigInteger current = getRandomInteger(BIT_LENGTH);
		while(current.compareTo(LARGE_PRIME) != -1){
			current = getRandomInteger(BIT_LENGTH);
		} */
		
		int randomDivisor = (int)((Math.random() * 20) + 5); /* generate a random divisor between 5 and 25 */
		BigInteger current = getRandomInteger(BIT_LENGTH);
		current = current.divide(new BigInteger(String.valueOf(randomDivisor)));
		return current;
	}
	
	public static void main(String[] args){
		BigInteger hpwd = Generator.getHPWD();
		System.out.println(hpwd);
		System.out.println(Generator.LARGE_PRIME);
	}

}
