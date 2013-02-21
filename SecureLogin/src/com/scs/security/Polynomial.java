package com.scs.security;

import java.math.BigDecimal;
import java.math.BigInteger;

public class Polynomial {

	private static final int MULTIPLIER = 1;
	private int degree;
	private double[] coefficients; /*
									 * [a(1), a(2), ...., a(m)] where
									 * polynomial is a(0)* x^0 + a(1)* x^1 + ...
									 * + a(m) * x^m
									 */
	private BigInteger zerothCoefficient;

	public static Polynomial getRandomPolynomial(int degree, BigInteger hpwd) {
		Polynomial p = new Polynomial(degree);
		p.setRandomCoefficients();
		p.setZerothCoefficient(hpwd);
		return p;
	}

	private void setRandomCoefficients() {
		for (int i = 0; i < degree; i++) {
			this.coefficients[i] = Math.random() * MULTIPLIER;
		}
	}
	
	private void setZerothCoefficient(BigInteger zerothCoefficient){
		this.zerothCoefficient = zerothCoefficient;
	}
	
	public BigInteger getZerothCoefficient(){
		return zerothCoefficient;
	}

	public Polynomial(int degree) {
		this.degree = degree;
		this.coefficients = new double[degree + 1];
	}

	/* evaluate the polynomial for a given x */
	public BigDecimal evaluate(BigDecimal x) {
		BigDecimal temp = new BigDecimal(x.toString());
		BigDecimal result = new BigDecimal(0);
		for (int i = 0; i < degree; i++) {
			result = result.add(temp.multiply(new BigDecimal(coefficients[i])));
			temp = temp.multiply(x);
		}
		result = result.add(new BigDecimal(zerothCoefficient.toString()));
		return result;
	}
	
	/* returns polynomial from a set of (degree + 1) points on it */
	public static Polynomial generatePolynomialFromPoints(Point[] points){
		return null;
	}

	public void display() {
		System.out.print("Polynomial : ");
		System.out.print("[" + zerothCoefficient.toString() + ", ");
		for (int i = 0; i < degree; i++) {
			if (i != degree - 1) {
				System.out.print(coefficients[i] + ", ");
			}else{
				System.out.print(coefficients[i] + "]");
			}
		}
		System.out.println();
	}

	public static void main(String[] args) {
		Polynomial p = Polynomial.getRandomPolynomial(2, new BigInteger("1000"));
		p.display();
		System.out.println(p.evaluate(new BigDecimal(1)));
	}
	
	public class Point{
		BigDecimal x;
		BigDecimal y;
		
		public Point(BigDecimal x, BigDecimal y) {
			super();
			this.x = x;
			this.y = y;
		}
		
		
	}

}
