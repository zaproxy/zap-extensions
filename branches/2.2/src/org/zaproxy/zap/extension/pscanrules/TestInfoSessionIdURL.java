/*
 *
 * Paros and its related class files.
 * 
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 * 
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/01/02 Separate param and attack
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2013/01/25 Removed the "(non-Javadoc)" comments.
// ZAP: 2013/03/03 Issue 546: Remove all template Javadoc comments
// ZAP: 2013/07/19 Issue 366: "Other Info" for "Session ID in URL rewrite" not always correct
// ZAP: 2013/10/12 Issue 809: Converted to a passive scan rule and added some new features
package org.zaproxy.zap.extension.pscanrules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Plugin refactored for URL ID session disclosure starting from the previous
 * Active plugin developed by Paros team
 *
 * @author yhawke
 *
 */
public class TestInfoSessionIdURL extends PluginPassiveScanner {
    /*
     * private static Pattern staticSessionCookieNamePHP = Pattern("PHPSESSID", PATTERN.PARAM);
     * ASP = ASPSESSIONIDxxxxx=xxxxxx
     * PHP = PHPSESSID
     * Cole fusion = CFID, CFTOKEN	(firmed, checked with Macromedia)
     * Java (tomcat, jrun, websphere, sunone, weblogic )= JSESSIONID=xxxxx
     *
     * List of session id available also on this site:
     * http://www.portent.com/blog/random/session-id-parameters-list.htm
     */

    // Inner Thread Parent variable
    private PassiveScanThread parent = null;

    /**
     * Get this plugin id
     *
     * @return the ZAP id
     */
    private int getId() {
        return 00003;
    }

    /**
     * Get the plugin name
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return "Session ID in URL rewrite";
    }

    private String getDescription() {
        return "URL rewrite is used to track user session ID. "
                + "The session ID may be disclosed in referer header. "
                + "Besides, the session ID can be stored in browser history or server logs.";
    }

    private String getSolution() {
        return "For secure content, put session ID in cookie. "
                + "To be even more secure consider to use a combination of cookie and URL rewrite.";
    }

    private String getReference() {
        return "http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html";
    }

    private int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    private int getCweId() {
        return 200;
    }

    private int getWascId() {
        return 13;
    }

    /**
     * Set the Scanner thred parent object
     * 
     * @param parent the PassiveScanThread parent object
     */
    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    /**
     * Scan the request. Currently it does nothing.
     * 
     * @param msg the HTTP message
     * @param id the id of the request
     */
    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        //do Nothing it's related to response managed
    }

    /**
     * Perform the passive scanning of url based session ids
     * 
     * @param msg the message that need to be checked
     * @param id the id of the session
     * @param source the source code of the response
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        // Simplify everything using only getQuery()???
        String uri = msg.getRequestHeader().getURI().toString();
        String sessionIdValue;
        String sessionIdName;
        Pattern pattern;
        Matcher matcher;

        // Alternative implementation
        // we search for all params looking for one session element
        // maybe more efficient because we don't build Patterns any time
        //String[] params = msg.getParamNames();

        // The Session ID list option param
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions =
                (HttpSessionsParam) options.getParamSet(HttpSessionsParam.class);

        // Loop on all possible 
        // session id variables (looking all along the url)
        // -----------------------------------------------------
        // We've to rebuild every time the patterns because
        // the user could change options during the session
        // so we have to be sure that we search for the 
        // session ids that have really been selected (or added)
        // -----------------------------------------------------
        for (String sessionid : sessionOptions.getDefaultTokensEnabled()) {
            pattern = Pattern.compile("(\\Q" + sessionid + "\\E)=[^\\&]+", Pattern.CASE_INSENSITIVE);
            matcher = pattern.matcher(uri);

            if (matcher.find()) {
                // Get the overall sessionvar=value pattern
                sessionIdValue = matcher.group(0);
                // Get the sessionvar name
                sessionIdName = matcher.group(1);

                // In passive mode there not exists any KB available
                // This was the old implementation
                // --------------------------------------------------
                //String kb = getKb().getString("sessionId/nameValue");
                //if (kb == null || !kb.equals(sessionIdValue)) {
                //    getKb().add("sessionId/nameValue", sessionIdValue);
                //    bingo(Alert.RISK_LOW, Alert.WARNING, uri, null, "", null, sessionIdValue, base);
                //}                
                //kb = getKb().getString("sessionId/name");
                //getKb().add("sessionId/name", sessionIdName);

                // Raise an alert according to Passive Scan Rule model
                // description, uri, param, attack, otherInfo, 
                // solution, reference, evidence, cweId, wascId, msg
                Alert alert = new Alert(getId(), getRisk(), Alert.WARNING, getName());
                alert.setDetail(
                        getDescription(),
                        uri,
                        sessionIdName,
                        sessionIdValue,
                        "",
                        getSolution(),
                        getReference(),
                        sessionIdValue, // evidence
                        getCweId(), // CWE Id
                        getWascId(), // WASC Id - Info leakage
                        msg);

                parent.raiseAlert(id, alert);

                // Now try to check if there exists a 
                // referer inside thecontent
                try {
                    checkSessionIDExposure(msg, id);

                } catch (URIException e) {
                }

                break;
            }
        }
    }
    
    // External link Response finder regex
    // HTML is very simple because only src/href exists
    // DOM based is very complex because you can have all these possibilities:
    // window.open('url
    // window.location='url
    // location.href='url
    // document.location='url
    // and also internal variables containing urls that can be
    // also dynamically composed along page execution
    // so we search only for pattern like these:
    // ='url or ('url beacuse it's suitable to all the previous possibilities
    // and we check for no quoted urls only if href or src
    // ---------------------------------
    private static final String EXT_LINK = "https?://([\\w\\.\\-_]+)";
    private static final Pattern[] EXT_LINK_PATTERNS = {
        //Pattern.compile("src\\s*=\\s*\"?" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        //Pattern.compile("href\\s*=\\s*\"?" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        Pattern.compile("src\\s*=\\s*[\"']" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        Pattern.compile("href\\s*=\\s*[\"']" + EXT_LINK, Pattern.CASE_INSENSITIVE),
        Pattern.compile("[=\\(]\\s*[\"']" + EXT_LINK, Pattern.CASE_INSENSITIVE)
    };

    // The name of this sub-alert
    private String getRefererAlert() {
        return "Referer expose session ID";
    }

    // The description of this sub-alert
    private String getRefererDescription() {
        return "Hyperlink to other host name is found. "
                + "As session ID URL rewrite is used, it may be disclosed in referer header to external host.";
    }

    // The solution of this sub-alert
    private String getRefererSolution() {
        return "This is a risk if the session ID is sensitive and the hyperlink refer to an external host. "
                + "For secure content, put session ID in secured session cookie.";
    }

    /**
     * Check if an external link is present inside a vulnerable url
     *
     * @param msg the message that need to be checked
     * @param id the id of the session
     * @throws URIException if there're some trouble with the Request
     */
    private void checkSessionIDExposure(HttpMessage msg, int id) throws URIException {
        //Vector<String> referrer = msg.getRequestHeader().getHeaders(HttpHeader.REFERER);
        int risk = (msg.getRequestHeader().isSecure()) ? Alert.RISK_MEDIUM : Alert.RISK_LOW;
        String body = msg.getResponseBody().toString();
        String host = msg.getRequestHeader().getURI().getHost();
        String linkHostName;
        Matcher matcher;

        for (Pattern pattern : EXT_LINK_PATTERNS) {
            matcher = pattern.matcher(body);

            if (matcher.find()) {
                linkHostName = matcher.group(1);
                if (host.compareToIgnoreCase(linkHostName) != 0) {

                    // Raise an alert according to Passive Scan Rule model
                    // description, uri, param, attack, otherInfo, 
                    // solution, reference, evidence, cweId, wascId, msg
                    Alert alert = new Alert(getId(), risk, Alert.WARNING, getRefererAlert());
                    alert.setDetail(
                            getRefererDescription(),
                            msg.getRequestHeader().getURI().getURI(),
                            "N/A",
                            linkHostName,
                            "",
                            getRefererSolution(),
                            getReference(),
                            linkHostName, // evidence
                            getCweId(), // CWE Id
                            getWascId(), // WASC Id - Info leakage
                            msg);

                    parent.raiseAlert(id, alert);

                    break;
                }
            }
        }
    }
}
