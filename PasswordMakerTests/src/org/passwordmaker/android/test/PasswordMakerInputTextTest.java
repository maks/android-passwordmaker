/*
 *  Copyright 2011 James Stapleton
 * 
 *  This file is part of PasswordMaker Pro For Android.
 *
 *  PasswordMaker Pro For Android is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  PasswordMaker Pro For Android is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with PasswordMaker Pro For Android.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.passwordmaker.android.test;

import org.passwordmaker.android.PasswordMaker;
import org.passwordmaker.android.PwmProfile;
import org.passwordmaker.android.PwmProfile.UrlComponents;

import junit.framework.TestCase;

public class PasswordMakerInputTextTest  extends TestCase {
	private final String testUrl1 = "http://www.google.com/search?q=password+maker";
	private final String testUrl2 = "http://www.google.com:8080/search?q=password+maker";
	private final String notAUrl = "This is Not A Url";
	
	private PasswordMaker pwm = new PasswordMaker();
	
	public PwmProfile _setupPwm() {
		pwm = new PasswordMaker();
		PwmProfile profile = pwm.getProfile();
		profile.getUrlComponents().clear();
		return profile;
	}
	
	public void testNoUrlParsing() {
		_setupPwm();
		assertEquals(testUrl1, pwm.getModifiedInputText(testUrl1));
	}
	
	public void testJustUseDomain() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Domain);
		assertEquals("google.com", pwm.getModifiedInputText(testUrl1));
	}
	
	public void testDomainPlusSubDomain() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.getUrlComponents().add(UrlComponents.Subdomain);
		assertEquals("www.google.com", pwm.getModifiedInputText(testUrl1));
	}
	
	public void testJustSubDomain() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Subdomain);
		String actual = pwm.getModifiedInputText(testUrl1);
		assertEquals("www", actual);
	}
	
	public void testJustPortPathAnchorQuery() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals("/search?q=password+maker", pwm.getModifiedInputText(testUrl1));
	}
	
	public void testDomainPlusPath() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals("google.com/search?q=password+maker", pwm.getModifiedInputText(testUrl1));
	}
	
	public void testProtocolPlusPath() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Protocol);
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals("http:///search?q=password+maker", pwm.getModifiedInputText(testUrl1));
	}
	
	public void testWithPortNumber() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Protocol);
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals("http://google.com:8080/search?q=password+maker", pwm.getModifiedInputText(testUrl2));
	}
	public void testWithJustPortNumber() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals(":8080/search?q=password+maker", pwm.getModifiedInputText(testUrl2));
	}
	
	public void testNotAUrl() {
		final PwmProfile profile = _setupPwm();
		profile.getUrlComponents().add(UrlComponents.Domain);
		profile.getUrlComponents().add(UrlComponents.Protocol);
		profile.getUrlComponents().add(UrlComponents.PortPathAnchorQuery);
		assertEquals(notAUrl , pwm.getModifiedInputText(notAUrl));
	}

	
	
}
