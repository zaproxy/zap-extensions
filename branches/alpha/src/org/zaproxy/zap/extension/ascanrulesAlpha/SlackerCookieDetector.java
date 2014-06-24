package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * Goal: automate discovery of areas of a website where authentication via
 * session cookies, or content controlled by preference cookies, is not actually
 * enforced.
 * 
 * Method: checks one by one if cookies really used for rendering a page at
 * given URI, based on length in bytes of response compared to baseline request.
 * 
 * For example if 5 cookies exist, 5 new GET requests executed, each time
 * dropping a different cookie and noting any change in the response length. A
 * site with only tracking cookies will get an INFO alert but may be working as
 * designed.
 * 
 * With thanks to Kaiser Permanente CyberSecurity comrades for using and
 * feedback.
 */
public class SlackerCookieDetector extends AbstractAppPlugin {
	// http://projects.webappsec.org/w/page/13246978/Threat%20Classification
	// going to classify this as #45, Fingerprinting.
	// #01, Authentication could be applicable.
	private static final String[] HIGH_RISK_COOKIE_NAMES = { "session", "userid" };
	private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");
	private static Logger log = Logger.getLogger(SlackerCookieDetector.class);

	@Override
	public void scan() {

		HttpMessage msg = getBaseMsg();
		try {
			sendAndReceive(msg, false);
		} catch (IOException io) {
			log.debug("Blew up trying to do BASE request :(");
		}

		int baseResponseLength = msg.getResponseBody().length();
		Set<HtmlParameter> cookies = msg.getCookieParams();

		Set<String> cookiesThatMakeADifference = new HashSet<String>();
		Set<String> cookiesThatDoNOTMakeADifference = new HashSet<String>();

		boolean thereAreSlackCookies = false;

		for (HtmlParameter oneCookie : cookies) {
			thereAreSlackCookies = repeatRequestWithoutOneCookie(msg, baseResponseLength, cookies,
					cookiesThatMakeADifference, cookiesThatDoNOTMakeADifference, thereAreSlackCookies,
					oneCookie);

			boolean sessionWentBad = refreshSessionAllCookies(msg, cookies, oneCookie, baseResponseLength);
			// Quit if active scanning has been stopped, or we lost session
			// integrity
			if (isStop() || sessionWentBad) {
				return;
			}
		}

		if (thereAreSlackCookies) {
			raiseAlert(msg, cookies, cookiesThatMakeADifference, cookiesThatDoNOTMakeADifference);
		}
	}

	private boolean refreshSessionAllCookies(HttpMessage msg, Set<HtmlParameter> cookies,
			HtmlParameter oneCookie, int baseResponseLength) {

		boolean sessionNoLongerGood = false;
		msg.setCookieParams(new TreeSet<HtmlParameter>(cookies));

		try {
			sendAndReceive(msg, false);
			if (msg.getResponseBody().length() != baseResponseLength) {
				sessionNoLongerGood = true;
				bingo(Alert.RISK_INFO,
				// reliability:
						Alert.SUSPICIOUS, msg.getRequestHeader().getURI().toString(),
						// parameter:
						null,
						// Attack:
						null,
						// Other info:
						getSessionDestroyedText(oneCookie.getName()),
						// Evidence:
						null, msg);
			}
		} catch (IOException io) {
			log.debug("Blew up trying to refresh session with all cookies: " + io.getMessage());
		}
		return sessionNoLongerGood;
	}

	/**
	 * This is where the real work happens, we resubmit a GET to same URI but
	 * dropping one cookie, and see if response is different.
	 */
	private boolean repeatRequestWithoutOneCookie(HttpMessage msg, int baseResponseLength,
			Set<HtmlParameter> cookies, Set<String> cookiesThatMakeADifference,
			Set<String> cookiesThatDoNOTMakeADifference, boolean thereAreSlackCookies, HtmlParameter oneCookie) {

		boolean doesCookieChangeResponse = sendOneRequest(cookies, oneCookie, baseResponseLength);
		if (doesCookieChangeResponse) {
			cookiesThatMakeADifference.add(oneCookie.getName());
		} else {
			thereAreSlackCookies = true;
			cookiesThatDoNOTMakeADifference.add(oneCookie.getName());
		}

		return thereAreSlackCookies;
	}

	/**
	 * Looks as if one needs to manually add cookies to each synthetic GET
	 * 
	 * @param cookies
	 * @param oneCookie
	 * @param baseResponseLength
	 */
	private boolean sendOneRequest(Set<HtmlParameter> cookies, HtmlParameter oneCookie, int baseResponseLength) {

		HttpMessage msg = getNewMsg();

		boolean doesThisCookieMatter = false;
		TreeSet<HtmlParameter> allCookiesExceptOne = new TreeSet<HtmlParameter>();
		for (HtmlParameter cookieCandidate : cookies) {
			if (cookieCandidate != oneCookie)
				allCookiesExceptOne.add(cookieCandidate);
		}
		msg.setCookieParams(allCookiesExceptOne);
		try {
			// Send the request and retrieve the response
			sendAndReceive(msg, false);
			int responseLength = msg.getResponseBody().length();

			log.debug("trying to exclude cookie " + oneCookie.getName() + ", request header=>"
					+ msg.getRequestHeader().getHeadersAsString());
			log.debug("response length was:" + responseLength + ", while baseResponseLength was: "
					+ baseResponseLength);

			if (responseLength != baseResponseLength) {
				doesThisCookieMatter = true;
			}

		} catch (IOException ex) {
			log.debug("caught IOException in SlackerCookieDetector: " + ex.getMessage());
		}
		return doesThisCookieMatter;
	}

	private void raiseAlert(HttpMessage msg, Set<HtmlParameter> cookies,
			Set<String> cookiesThatMakeADifference, Set<String> cookiesThatDoNOTMakeADifference) {

		StringBuffer otherInfoBuff = createOtherInfoText(cookiesThatMakeADifference,
				cookiesThatDoNOTMakeADifference);

		int riskLevel = calculateRisk(cookiesThatDoNOTMakeADifference, otherInfoBuff);

		bingo(riskLevel,
		// reliability:
				Alert.SUSPICIOUS, msg.getRequestHeader().getURI().toString(),
				// parameter:
				null,
				// Attack:
				null,
				// Other info:
				otherInfoBuff.toString(),
				// Evidence:
				null, msg);
	}

	private StringBuffer createOtherInfoText(Set<String> cookiesThatMakeADifference,
			Set<String> cookiesThatDoNOTMakeADifference) {

		StringBuffer otherInfoBuff = new StringBuffer(
				Constant.messages.getString("ascanalpha.cookieslack.otherinfo.intro"));

		otherInfoBuff.append(getAffectResponseYes());
		listCookies(cookiesThatMakeADifference, otherInfoBuff);

		otherInfoBuff.append(getAffectResponseNo());
		listCookies(cookiesThatDoNOTMakeADifference, otherInfoBuff);

		return otherInfoBuff;
	}

	private void listCookies(Set<String> cookieSet, StringBuffer otherInfoBuff) {
		Iterator<String> itYes = cookieSet.iterator();
		while (itYes.hasNext()) {
			formatCookiesList(otherInfoBuff, itYes);
		}
		otherInfoBuff.append(getEOL());
	}

	private int calculateRisk(Set<String> cookiesThatDoNOTMakeADifference, StringBuffer otherInfoBuff) {
		int riskLevel = Alert.RISK_INFO;
		for (String cookie : cookiesThatDoNOTMakeADifference) {
			for (String risky_cookie : HIGH_RISK_COOKIE_NAMES) {
				if (cookie.toLowerCase().indexOf(risky_cookie) > -1) {
					// time to worry: we dropped a likely session cookie, but no
					// change in response
					riskLevel = Alert.RISK_LOW;
					otherInfoBuff.insert(0, getSessionCookieWarning(cookie));
				}
			}
		}
		return riskLevel;
	}

	private String getSessionDestroyedText(String cookie) {
		return Constant.messages.getString("ascanalpha.cookieslack.session.destroyed", cookie);
	}

	private String getAffectResponseYes() {
		return Constant.messages.getString("ascanalpha.cookieslack.affect.response.yes");
	}

	private String getAffectResponseNo() {
		return Constant.messages.getString("ascanalpha.cookieslack.affect.response.no");
	}

	private String getSeparator() {
		return Constant.messages.getString("ascanalpha.cookieslack.separator");
	}

	private String getEOL() {
		return Constant.messages.getString("ascanalpha.cookieslack.endline");
	}

	private void formatCookiesList(StringBuffer otherInfoBuff, Iterator<String> cookieIterator) {

		otherInfoBuff.append(cookieIterator.next());
		if (cookieIterator.hasNext()) {
			otherInfoBuff.append(getSeparator());
		}
	}

	private String getSessionCookieWarning(String cookie) {
		return Constant.messages.getString("ascanalpha.cookieslack.session.warning", cookie);
	}

	/**
	 * This should be unique across all active and passive rules. The master
	 * list:
	 * http://code.google.com/p/zaproxy/source/browse/trunk/src/doc/alerts.xml
	 */
	@Override
	public int getId() {
		return 90027;
	}

	@Override
	public String getName() {
		return Constant.messages.getString("ascanalpha.cookieslack.name");
	}

	@Override
	public String[] getDependency() {
		return null;
	}

	@Override
	public String getDescription() {
		return Constant.messages.getString("ascanalpha.cookieslack.desc");
	}

	@Override
	public int getCategory() {
		return Category.INFO_GATHER;
	}

	@Override
	public String getSolution() {
		return Constant.messages.getString("ascanalpha.cookieslack.solution");
	}

	@Override
	public String getReference() {
		if (vuln != null) {
			StringBuilder sb = new StringBuilder();
			for (String ref : vuln.getReferences()) {
				if (sb.length() > 0) {
					sb.append("\n");
				}
				sb.append(ref);
			}
			return sb.toString();
		}
		return "Cookie Slack Detector: Failed to load vulnerability reference from file";
	}

	@Override
	public void init() {

	}

	@Override
	public int getRisk() {
		return Alert.RISK_INFO;
	}

	@Override
	public int getCweId() {
		// The CWE id - 200 is closest thing to fingerprinting
		return 200;
	}

	@Override
	public int getWascId() {
		// The WASC ID - fingerprinting
		return 45;
	}

}

