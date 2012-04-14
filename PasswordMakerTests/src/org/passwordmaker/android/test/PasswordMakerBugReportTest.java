package org.passwordmaker.android.test;

import org.passwordmaker.android.CharacterSetSelection;
import org.passwordmaker.android.HashAlgo;
import org.passwordmaker.android.PasswordMaker;
import org.passwordmaker.android.PwmProfile;
import org.passwordmaker.android.PwmProfile.UrlComponents;

import junit.framework.TestCase;

public class PasswordMakerBugReportTest extends TestCase {
	private PasswordMaker pwm = new PasswordMaker();
	
	public PwmProfile _setupPwm() {
		pwm = new PasswordMaker();
		PwmProfile profile = pwm.getProfile();
		profile.getUrlComponents().clear();
		return profile;
	}
	
	public void testPeteBugReport1() {
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.HMAC_RIPEMD_160);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.alphaNum);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("Sdng", pwm.generatePassword("google.com", "secret"));
	}
	
	public void testPeteBugReport2() {
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.HMAC_SHA_256_Version_1_5_1);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.alphaNum);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("JyGs", pwm.generatePassword("google.com", "secret"));
	}
	
	public void testPeteBugReport3() {
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.HMAC_MD4);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.alphaNum);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("68tV", pwm.generatePassword("google.com", "secret"));
	}
	
	public void testPeteBugReport4() {
		// note passwordmaker.org/passwordmaker.html forced characters 
		// to be just hex
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.MD5_Version_0_6);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.hex);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("646d", pwm.generatePassword("google.com", "secret"));
		profile.setCharacters(CharacterSetSelection.alphaNum);
		assertEquals("646d", pwm.generatePassword("google.com", "secret"));
	}
	
	public void testPeteBugReport5() {
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.MD4);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.alphaNum);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("EQ76", pwm.generatePassword("google.com", "secret"));
	}
	
	public void testPeteBugReport6() {
		// note passwordmaker.org/passwordmaker.html forced characters 
		// to be just hex
		final PwmProfile profile = _setupPwm();
		profile.setHashAlgo(HashAlgo.HMAC_MD5_Version_0_6);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.setCharacters(CharacterSetSelection.hex);
		profile.setLengthOfPassword((short)4);
		assertEquals("google.com" , pwm.getModifiedInputText("google.com"));
		assertEquals("1480", pwm.generatePassword("google.com", "secret"));
		profile.setCharacters(CharacterSetSelection.alphaNum);
		assertEquals("1480", pwm.generatePassword("google.com", "secret"));
	}
}
