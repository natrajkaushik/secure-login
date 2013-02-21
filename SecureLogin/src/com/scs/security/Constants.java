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
		"What is the time of the day?"
	};
	
	/**
	 * Number of features
	 */
	public static final int M = QUESTIONS.length;
	
	/**
	 * Number of previous successful logins stored
	 */
	public static final int H = 10;
	
	/**
	 * String written to history file to know if
	 * decryption was successful or not
	 */
	public static final String TOTEM = "BECOOLHONEYBUNNY";
	
}