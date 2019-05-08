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
// ZAP: 2014/11/09 Issue 1396: Add min length check to reduce false positives
// ZAP: 2015/09/23 Issue 1594: Change matching mechanism
// ZAP: 2017/11/10 Remove N/A from alert parameter.
package org.zaproxy.zap.extension.pscanrules;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.htmlparser.jericho.Source;

import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Plugin refactored for URL ID session disclosure starting from the previous
 * Active plugin developed by Paros team
 *
 * @author yhawke
 * @author kingthorin+owaspzap
 *
 */
public class TestInfoSessionIdURL extends PluginPassiveScanner {
	
	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.testinfosessionidurl.";
	
	private static final int SESSION_TOKEN_MIN_LENGTH = 8; 
	
    /*
     * private static Pattern staticSessionCookieNamePHP = Pattern("PHPSESSID", PATTERN.PARAM);
     * ASP = ASPSESSIONIDxxxxx=xxxxxx
     * PHP = PHPSESSID
     * Cold fusion = CFID, CFTOKEN	(firmed, checked with Macromedia)
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
    @Override
    public int getPluginId() {
        return 00003;
    }

    /**
     * Get the plugin name
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "refs");
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
     * Set the Scanner thread parent object
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
     * Perform the passive scanning of URL based session IDs
     * 
     * @param msg the message that need to be checked
     * @param id the id of the session
     * @param source the source code of the response
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        TreeSet<HtmlParameter> urlParams = msg.getUrlParams();
        
        
        String uri = msg.getRequestHeader().getURI().toString();
        boolean found = false;
        
        // The Session ID list from option param (panel)
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);
        List<String> sessionIds = Collections.emptyList();
        if (sessionOptions != null) {
            sessionIds = sessionOptions.getDefaultTokensEnabled();
        }
	if(!urlParams.isEmpty()) {
            for (HtmlParameter param: urlParams) { //Iterate through the parameters
            	//If the parameter name is one of those on the Session Token list from the options panel
            	if (sessionIds.contains(param.getName().toLowerCase(Locale.ROOT))) { 
            		//If the param value length is greater than MIN_LENGTH (therefore there is a value)
            		if (param.getValue().length() > SESSION_TOKEN_MIN_LENGTH) {
    	                // Raise an alert according to Passive Scan Rule model
    	                // description, uri, param, attack, otherInfo, 
    	                // solution, reference, evidence, cweId, wascId, msg
    	                Alert alert = new Alert(getPluginId(), getRisk(), Alert.CONFIDENCE_HIGH, getName());
    	                alert.setDetail(
    	                        getDescription(),
    	                        uri,
    	                        param.getName(), // param
    	                        "", // attack
    	                        "", // otherinfo
    	                        getSolution(),
    	                        getReference(),
    	                        param.getValue(), // evidence
    	                        getCweId(), // CWE Id
    	                        getWascId(), // WASC Id - Info leakage
    	                        msg);
    	
    	                parent.raiseAlert(id, alert);
    	                // We don't break on this one.
    	                // There shouldn't be more than one per URL but bizarre things do happen.
    	                // Improbable doesn't mean impossible.
    	                found = true;
            		}
            	}
            }
        }
        if (!found && msg.getRequestHeader().getURI().getEscapedPath() != null) {
            //Handle jsessionid like: http://tld.gtld/fred;jsessionid=1A530637289A03B07199A44E8D531427?foo=bar
            Matcher jsessMatcher = null;
            try {
                jsessMatcher = Pattern.compile("jsessionid=[\\dA-Z]*", Pattern.CASE_INSENSITIVE).matcher(msg.getRequestHeader().getURI().getPath());
            } catch (URIException e) {
            }
            if (jsessMatcher != null && jsessMatcher.find() && sessionIds.contains(jsessMatcher.group().split("=")[0].trim())) {
                Alert alert = new Alert(getPluginId(), getRisk(), Alert.CONFIDENCE_HIGH, getName());
                alert.setDetail(
                        getDescription(),
                        uri,
                       "", // param
                        "", // attack
                        "", // otherinfo
                        getSolution(),
                        getReference(),
                        jsessMatcher.group(), // evidence
                        getCweId(), // CWE Id
                        getWascId(), // WASC Id - Info leakage
                        msg);
            
                parent.raiseAlert(id, alert);
                found = true;
            }
        }
        if (found) {
	        // Now try to check if there exists a referer inside the content
            // i.e.: There is an external link for which 
            // a referer header would be passed including this session token
            try {
                checkSessionIDExposure(msg, id);
            } catch (URIException e) {
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
    // ='url or ('url because it's suitable to all the previous possibilities
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
    	return Constant.messages.getString(MESSAGE_PREFIX + "referrer.alert");
    }

    // The description of this sub-alert
    private String getRefererDescription() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "referrer.desc");
    }

    // The solution of this sub-alert
    private String getRefererSolution() {
    	return Constant.messages.getString(MESSAGE_PREFIX + "referrer.soln");
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
                    Alert alert = new Alert(getPluginId(), risk, Alert.CONFIDENCE_MEDIUM, getRefererAlert());
                    alert.setDetail(
                            getRefererDescription(),
                            msg.getRequestHeader().getURI().getURI(),
                            "",
                            linkHostName,
                            "",
                            getRefererSolution(),
                            getReference(),
                            linkHostName, // evidence
                            getCweId(), // CWE Id
                            getWascId(), // WASC Id - Info leakage
                            msg);

                    parent.raiseAlert(id, alert);

                    break; // Only need one
                }
            }
        }
    }
}
