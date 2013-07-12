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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.net.HttpCookie;
import java.util.LinkedList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Vector;

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
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
public class CookieLooselyScopedScanner extends PluginPassiveScanner {
	
	private PassiveScanThread parent = null;

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanbeta.cookielooselyscoped.";

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {		
		List<HttpCookie> cookies = msg.getResponseHeader().getHttpCookies();
		
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
			sbCookies.append(Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.cookie", cookie));
		}		
		
		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), null, getExploitMessage(), 
				Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", host, sbCookies),
				getSolutionMessage(), getReferenceMessage(), 
				"",	// No Evidence
				0,	// TODO CWE Id
				0,	// TODO WASC Id
				msg);

		parent.raiseAlert(id, alert);
	}

	private int getId() {
		return 90033;
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "exploit");
	}
}