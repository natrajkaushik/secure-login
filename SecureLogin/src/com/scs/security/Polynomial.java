package com.scs.security;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

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
	
	/* returns zeroth coefficient of polynomial from a set of (degree + 1) points on it 
	 * 
	 * Not sure about the implementation - need to run this method to test if working
	 * */
	public static BigInteger generateZerothCoefficientFromPoints(List<Point> points){
		List<BigDecimal> xValues = new ArrayList<BigDecimal>();
		for(int i = 0; i < points.size(); i++){
			xValues.add(points.get(i).x);
		}
		
		List<BigDecimal> yValues = new ArrayList<BigDecimal>();
		for(int i = 0; i < points.size(); i++){
			yValues.add(points.get(i).y);
		}
		
		/* Lagrange Interpolation */
		BigDecimal sum = new BigDecimal("0");
		for(int i = 0; i < points.size(); i++){
			BigDecimal lambda = getLambda(xValues, i);
			sum = sum.add(yValues.get(i).multiply(lambda));
		}
		
		BigInteger result = sum.toBigInteger().mod(Constants.Q); /* this can cause trouble */
		
		return result;
	}
	
	private static BigDecimal getLambda(List<BigDecimal> xValues, int index){
		BigDecimal result = new BigDecimal(1);
		
		for(int i = 0; i < xValues.size(); i++){
			BigDecimal current = xValues.get(i); 
			if(i != index){
				result = result.multiply(current.divide(current.subtract(xValues.get(index))));
			}
		}
		
		return result;
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
	
	public static Point getPoint(BigDecimal x, BigDecimal y){
		Point p = new Point(x, y);
		return p;
	}

	public static void main(String[] args) {
		Polynomial p = Polynomial.getRandomPolynomial(2, new BigInteger("1000"));
		p.display();
		System.out.println(p.evaluate(new BigDecimal(1)));
	}

}

class Point{
	BigDecimal x;
	BigDecimal y;
	
	public Point(BigDecimal x, BigDecimal y) {
		super();
		this.x = x;
		this.y = y;
	}
	
	
}
