package com.scs.security;

public class Constants {
	/**
	 * Set of features
	 */
	public static final String[] QUESTIONS = {
			"How far are you from the campus right now?",
			"How many websites will you visit?",
			"How many emails will you exchange?",
			"How long will your session last?",
			"How many people will you message?",
			"How many browser plugins do you have installed?" };
	
	/**
	 * Threshold values of the features 
	 */
	public static final long[] THRESHOLD_FEATURE_VALUES = {2, 8, 3, 20, 6, 20};

	/**
	 * Number of features
	 */
	public static final int M = QUESTIONS.length;

	/**
	 * Number of previous successful logins stored
	 */
	public static final int H = 10;

	/**
	 * String written to history file to know if decryption was successful or
	 * not
	 */
	public static final String TOTEM = "BECOOLHONEYBUNNY";
}
