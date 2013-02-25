package com.scs.security;

import java.util.prefs.Preferences;

/***
 * Handles interfacing with the user
 */
public class LoginHandler {
	
	/* preferences for the authentication system */
	private static Preferences prefs;
	
	static{
		prefs = Preferences.userNodeForPackage(LoginHandler.class);
	}
	
	public static Preferences getPreferences(){
		return prefs;
	}
	
	
	private String password; /* user entered password */
	private long[] features = new long[Constants.M]; /* user entered features */
	
	
	
	/***
	 *  interact with the user and fetch the password and feature vector for a login attempt session
	 *  
	 */
	private void getUserInput(){
		System.out.println("******** SECURE LOGIN ********");
		System.out.println("Password : ");
		password = IOUtils.readFromConsole();
		readFeatures();
	}
	
	/***
	 *  interact with the user and fetch password for scheme initialization 
	 *  
	 */
	private void getSchemeInitializationInput(){
		System.out.println("******** SECURE LOGIN SETUP ********");
		System.out.println("Set Password : ");
		password = IOUtils.readFromConsole();
		readFeatures();
	}
	
	private void readFeatures(){
		String answer;
		for(int i = 0; i < Constants.QUESTIONS.length; i++){
			System.out.println(Constants.QUESTIONS[i]);
			answer = IOUtils.readFromConsole();
			if(answer == null || answer.isEmpty()){
				features[i] = Constants.THRESHOLD_FEATURE_VALUES[i];
			}else{
				try{
					features[i] = Long.valueOf(answer);
				}catch(NumberFormatException e){
					// features[i] = Constants.THRESHOLD_FEATURE_VALUES[i];
					System.err.println("Invalid feature value!");
					System.exit(-1);
				}
			}
		}
	}
		
	/***
	 * @return true if user is successfully authenticated
	 */
	public boolean authenticate(){
		getUserInput();
		return Authenticator.authenticate(password, features);
	}
	
	/***
	 * @return true if scheme is successfully setup
	 */
	public boolean initScheme(){
		getSchemeInitializationInput();
		return Authenticator.initScheme(password, features);
	}
	
	public static LoginHandler getLoginHandler(){
		return new LoginHandler();
	}
	
	/***
	 * Main workflow
	 * @param args : args[0] may contain RESET
	 */
	public static void main(String[] args){
		if(args.length > 0 && Constants.RESET.equals(args[0])){
			/* If RESET is specified, clear the scheme preferences */
			Authenticator.reset();
		}
		LoginHandler lHandler = getLoginHandler();
		if (Authenticator.isSchemeInitialized()){
			boolean check = lHandler.authenticate();
			if(check){
				System.out.println("You have been successfully authenticated!");
			}else{
				System.out.println("Authentication failed!");
			}
		} else{
			lHandler.initScheme();
			System.out.println("Password successfully setup !!");
		}
	}
}