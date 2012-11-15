/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.cookielooselyscopedpscan;

import java.net.HttpCookie;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvCookieLooselyScope}
 * 
 * http://websecuritytool.codeplex.com/SourceControl/changeset/view/17f2e3ded58f#Watcher%20Check%20Library%2fCheck.Pasv.Cookie.LooselyScoped.cs
 */
public class CookieLooselyScopedPassiveScanner extends PluginPassiveScanner {
	
	private PassiveScanThread parent = null;

	/**
	 * contains the internationalisation (i18n) messages. Must be statically
	 * initialised, since messages is accessed before the plugin is initialised
	 * (using init)
	 */
	private final ResourceBundle messages = ResourceBundle.getBundle(this
			.getClass().getPackage().getName()
			+ ".Messages", Constant.getLocale());

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "cookielooselyscoped.";

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zaproxy.zap.extension.pscan.PassiveScanner#getName()
	 */
	@Override
	public String getName() {
		return getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.zaproxy.zap.extension.pscan.PassiveScanner#scanHttpResponseReceive
	 * (org.parosproxy.paros.network.HttpMessage, int,
	 * net.htmlparser.jericho.Source)
	 */
	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {		
		List<HttpCookie> cookies = getHttpCookies(msg);
		
		// name of a host from which the response has been sent from
		String host = msg.getRequestHeader().getHostName();
				
		// find all loosely scoped cookies
		List<HttpCookie> looselyScopedCookies = new LinkedList<HttpCookie>();
		for (HttpCookie cookie: cookies) {
			if (isLooselyScopedCookie(cookie, host)) {
				looselyScopedCookies.add(cookie);
			}
		}
		
		// raise alert if have found any loosely scoped cookies
		if (looselyScopedCookies.size() > 0) {
			raiseAlert(msg, id, host, looselyScopedCookies);
		}
	}

	// TODO: Fix in 2.0.0 - use msg.getResponseHeader().getHttpCookies()
	private List<HttpCookie> getHttpCookies(HttpMessage msg) {
		List<HttpCookie> cookies = new LinkedList<HttpCookie>();

		Vector<String> cookiesS = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE);
		if (cookiesS != null)
			for (String c : cookiesS)
				cookies.addAll(HttpCookie.parse(c));

		cookiesS = msg.getResponseHeader().getHeaders(HttpHeader.SET_COOKIE2);
		if (cookiesS != null)
			for (String c : cookiesS)
				cookies.addAll(HttpCookie.parse(c));

		return cookies;
	}

	/*
	 * Determines whether the specified cookie is loosely scoped by
	 * checking it's Domain attribute value agains the host
	 */
	private boolean isLooselyScopedCookie(HttpCookie cookie, String host) {
		// preconditions
		assert cookie != null;
		assert host != null;
		
		String cookieDomain = cookie.getDomain();
		
		// if Domain attribute hasn't been specified, the cookie
		// is scoped with the response host
		if (cookieDomain == null) {
			return false;
		}
		
		// Split cookie domain into sub-domains
		String[] cookieDomains = cookie.getDomain().split("\\.");
		// Split host FQDN into sub-domains
		String[] hostDomains = host.split("\\.");		
		
		// if cookie domain doesn't start with '.', and the domain is
		// not a second-level domain (example.com), the cookie Domain and 
		// host values should match exactly
		if (!cookieDomain.startsWith(".") && cookieDomains.length > 2) {
			return cookieDomain.equals(host);
		}
		
		// otherwise, remove the '.' and compare the result with the host
		if (cookieDomains.length != 2) {
			cookieDomains = cookieDomain.substring(1).split("\\.");
		}
		
		// loosely scoped domain name should have fewer sub-domains
		if (cookieDomains.length == 0 || cookieDomains.length >= hostDomains.length) {
			return false;			
		}
		
		// and those sub-domains should match the right most sub-domains of the 
		// origin domain name
		for (int i = 1; i <= cookieDomains.length; i++) {
			if (!cookieDomains[cookieDomains.length - i].equalsIgnoreCase(
					hostDomains[hostDomains.length - i])) {
				return false;
			}
		}
		
		// so, the right-most domains matched, the cookie is loosely scoped		
		return true;
	}

	private void raiseAlert(HttpMessage msg, int id, String host, List<HttpCookie> looselyScopedCookies) {
		Alert alert = new Alert(getId(), Alert.RISK_INFO, Alert.SUSPICIOUS,
				getName());
		StringBuilder sbCookies = new StringBuilder();
		for (HttpCookie cookie: looselyScopedCookies) {
			sbCookies.append(getString(MESSAGE_PREFIX + "extrainfo.cookie", cookie));
		}		
		
		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), null, getExploitMessage(), 
				getString(MESSAGE_PREFIX + "extrainfo", host, sbCookies),
				getSolutionMessage(), getReferenceMessage(), msg);

		parent.raiseAlert(id, alert);
	}

	private int getId() {
		return 90033;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.zaproxy.zap.extension.pscan.PassiveScanner#setParent(org.zaproxy.
	 * zap.extension.pscan.PassiveScanThread)
	 */
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/**
	 * Returns an internationalized message for the specified key
	 * 
	 * @param key
	 *            the key to look up the internationalized message
	 * @return the internationalized message corresponding to the key
	 */
	private String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * Returns an internationalized message for the specified key, using the
	 * parameters supplied
	 * 
	 * @param key
	 *            the key to look up the internationalized message
	 * @param params
	 *            the parameters to use for the internationalized message
	 * @return the internationalized message corresponding to the key, using the
	 *         parameters supplied
	 */
	public String getString(String key, Object... params) {
		try {
			return MessageFormat.format(messages.getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage() {
		return getString(MESSAGE_PREFIX + "exploit");
	}
}
