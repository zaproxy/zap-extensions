/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.net.URL;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HtmlParameter.Type;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;

/**
 * The SessionFixationScanRule identifies Session Fixation vulnerabilities with - cookie fields (a
 * more common scenario, but also more secure, even when the vulnerability occurs) - url fields
 * (less common, but also less secure when the vulnerability occurs) - session ids built into the
 * url path, and typically extracted by means of url rewriting TODO: implement a check for session
 * fixation issues on form parameters (by checking what?? resulting form params?)
 *
 * @author 70pointer
 */
public class SessionFixationScanRule extends AbstractAppPlugin {

    /** for logging. */
    private static Logger log = Logger.getLogger(SessionFixationScanRule.class);

    /** determines if we should output Debug level logging */
    private boolean debugEnabled = log.isDebugEnabled();

    @Override
    public int getId() {
        return 40013;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sessionfixation.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.sessionfixation.desc");
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.sessionfixation.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.sessionfixation.refs");
    }

    @Override
    public void init() {
        // DEBUG: turn on for debugging
        // TODO: turn this off
        // log.setLevel(org.apache.log4j.Level.DEBUG);
        // this.debugEnabled = true;

        if (this.debugEnabled) log.debug("Initialising");
    }

    /**
     * scans all GET, Cookie params for Session fields, and looks for Session Fixation
     * vulnerabilities
     */
    @Override
    public void scan() {

        // TODO: scan the POST (form) params for session id fields.
        try {
            boolean loginUrl = false;

            // Are we dealing with a login url in any of the contexts of which this uri is part
            URI requestUri = getBaseMsg().getRequestHeader().getURI();
            ExtensionAuthentication extAuth =
                    (ExtensionAuthentication)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionAuthentication.NAME);

            // using the session, get the list of contexts for the url
            List<Context> contextList =
                    extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());

            // now loop, and see if the url is a login url in each of the contexts in turn...
            for (Context context : contextList) {
                URI loginUri = extAuth.getLoginRequestURIForContext(context);
                if (loginUri != null && requestUri.getPath() != null) {
                    if (requestUri.getScheme().equals(loginUri.getScheme())
                            && requestUri.getHost().equals(loginUri.getHost())
                            && requestUri.getPort() == loginUri.getPort()
                            && requestUri.getPath().equals(loginUri.getPath())) {
                        // we got this far.. only the method (GET/POST), user details, query params,
                        // fragment, and POST params
                        // are possibly different from the login page.
                        loginUrl = true;
                        break;
                    }
                }
            }

            // For now (from Zap 2.0), the Session Fixation scan rule will only run for login pages
            if (loginUrl == false) {
                log.debug(
                        "For the Session Fixation scan rule to actually do anything, a Login Page *must* be set!");
                return;
            }
            // find all params set in the request (GET/POST/Cookie)
            // Note: this will be the full set, before we delete anything.

            TreeSet<HtmlParameter> htmlParams = new TreeSet<>();
            htmlParams.addAll(
                    getBaseMsg()
                            .getRequestHeader()
                            .getCookieParams()); // request cookies only. no response cookies
            htmlParams.addAll(getBaseMsg().getFormParams()); // add in the POST params
            htmlParams.addAll(getBaseMsg().getUrlParams()); // add in the GET params

            // Now add in the pseudo parameters set in the URL itself, such as in the following:
            // http://www.example.com/someurl;JSESSIONID=abcdefg?x=123&y=456
            // as opposed to the url parameters in the following example, which are already picked
            // up by getUrlParams()
            // http://www.example.com/someurl?JSESSIONID=abcdefg&x=123&y=456

            // convert from org.apache.commons.httpclient.URI to a String
            String requestUrl = "Unknown URL";
            try {
                requestUrl =
                        new URL(
                                        requestUri.getScheme(),
                                        requestUri.getHost(),
                                        requestUri.getPort(),
                                        requestUri.getPath())
                                .toString();
            } catch (Exception e) {
                // no point in continuing. The URL is invalid.  This is a peculiarity in the Zap
                // core,
                // and can happen when
                // - the user browsed to http://www.example.com/bodgeit and
                // - the user did not browse to http://www.example.com or to http://www.example.com/
                // so the Zap GUI displays "http://www.example.com" as a node under "Sites",
                // and under that, it displays the actual urls to which the user browsed
                // (http://www.example.com/bodgeit, for instance)
                // When the user selects the node "http://www.example.com", and tries to scan it
                // with
                // the session fixation scan rule, the URI that is passed is
                // "http://www.example.com",
                // which is *not* a valid url.
                // If the user actually browses to "http://www.example.com" (even without the
                // trailing slash)
                // the web browser appends the trailing slash, and so Zap records the URI as
                // "http://www.example.com/", which IS a valid url, and which can (and should) be
                // scanned.
                //
                // In short.. if this happens, we do not want to scan the URL anyway
                // (because the user never browsed to it), so just do nothing instead.

                log.error("Cannot convert URI [" + requestUri + "] to a URL: " + e.getMessage());
                return;
            }

            // suck out any pseudo url parameters from the url
            Set<HtmlParameter> pseudoUrlParams = getPseudoUrlParameters(requestUrl);
            htmlParams.addAll(pseudoUrlParams);
            if (this.debugEnabled)
                log.debug(
                        "Pseudo url params of URL ["
                                + requestUrl
                                + "] : ["
                                + pseudoUrlParams
                                + "]");

            //// for each parameter in turn,
            // int counter = 0;
            for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {

                HttpMessage msg1Final;
                HttpMessage msg1Initial = getNewMsg();

                //// debug logic only.. to do first field only
                // counter ++;
                // if ( counter > 1 )
                //	return;

                HtmlParameter currentHtmlParameter = iter.next();

                // Useful for debugging, but I can't find a way to view this data in the GUI, so
                // leave it out for now.
                // msg1Initial.setNote("Message 1 for parameter "+ currentHtmlParameter);

                if (this.debugEnabled)
                    log.debug(
                            "Scanning URL ["
                                    + msg1Initial.getRequestHeader().getMethod()
                                    + "] ["
                                    + msg1Initial.getRequestHeader().getURI()
                                    + "], ["
                                    + currentHtmlParameter.getType()
                                    + "] field ["
                                    + currentHtmlParameter.getName()
                                    + "] with value ["
                                    + currentHtmlParameter.getValue()
                                    + "] for Session Fixation");

                if (currentHtmlParameter.getType().equals(HtmlParameter.Type.cookie)) {

                    // careful to pick up the cookies from the Request, and not to include cookies
                    // set in any earlier response
                    TreeSet<HtmlParameter> cookieRequestParams =
                            msg1Initial.getRequestHeader().getCookieParams();
                    // delete the original cookie from the parameters
                    cookieRequestParams.remove(currentHtmlParameter);
                    msg1Initial.setCookieParams(cookieRequestParams);

                    // send the message, minus the cookie parameter, and see how it comes back.
                    // Note: do NOT automatically follow redirects.. handle those here instead.
                    sendAndReceive(msg1Initial, false, false);

                    /////////////////////////////
                    // create a copy of msg1Initial to play with to handle redirects (if any).
                    // we use a copy because if we change msg1Initial itself, it messes the URL and
                    // params displayed on the GUI.

                    msg1Final = msg1Initial;
                    HtmlParameter cookieBack1 =
                            getResponseCookie(msg1Initial, currentHtmlParameter.getName());
                    long cookieBack1TimeReceived =
                            System.currentTimeMillis(); // in ms.  when was the cookie received?
                    // Important if it has a Max-Age directive
                    Date cookieBack1ExpiryDate = null;

                    HttpMessage temp = msg1Initial;

                    int redirectsFollowed1 = 0;
                    while (HttpStatusCode.isRedirection(temp.getResponseHeader().getStatusCode())) {

                        // Note that we need to clone the Request and the Response..
                        // we seem to need to track the secure flag now to make sure its set later
                        boolean secure1 = temp.getRequestHeader().isSecure();
                        temp = temp.cloneAll(); // clone the previous message

                        redirectsFollowed1++;
                        if (redirectsFollowed1 > 10) {
                            throw new Exception(
                                    "Too many redirects were specified in the first message");
                        }
                        // create a new URI from the absolute location returned, and interpret it as
                        // escaped
                        // note that the standard says that the Location returned should be
                        // absolute, but it ain't always so...
                        URI newLocation =
                                new URI(
                                        temp.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                        true);

                        // and follow the forward url
                        // need to clear the params (which would come from the initial POST,
                        // otherwise)
                        temp.getRequestHeader().setGetParams(new TreeSet<HtmlParameter>());
                        temp.setRequestBody("");
                        temp.setResponseBody(
                                ""); // make sure no values accidentally carry from one iteration to
                        // the next
                        try {
                            temp.getRequestHeader().setURI(newLocation);
                        } catch (Exception e) {
                            // the Location field contents may not be standards compliant. Lets
                            // generate a uri to use as a workaround where a relative path was
                            // given instead of an absolute one
                            URI newLocationWorkaround =
                                    new URI(
                                            temp.getRequestHeader().getURI(),
                                            temp.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                            true);
                            // try again, except this time, if it fails, don't try to handle it
                            if (this.debugEnabled)
                                log.debug(
                                        "The Location ["
                                                + newLocation
                                                + "] specified in a redirect was not valid. Trying workaround url ["
                                                + newLocationWorkaround
                                                + "]");
                            temp.getRequestHeader().setURI(newLocationWorkaround);
                        }
                        temp.getRequestHeader().setSecure(secure1);
                        temp.getRequestHeader().setMethod(HttpRequestHeader.GET);
                        temp.getRequestHeader()
                                .setContentLength(
                                        0); // since we send a GET, the body will be 0 long
                        if (cookieBack1 != null) {
                            // if the previous request sent back a cookie, we need to set that
                            // cookie when following redirects, as a browser would
                            if (this.debugEnabled)
                                log.debug("Adding in cookie [" + cookieBack1 + "] for a redirect");
                            TreeSet<HtmlParameter> forwardCookieParams =
                                    temp.getRequestHeader().getCookieParams();
                            forwardCookieParams.add(cookieBack1);
                            temp.getRequestHeader().setCookieParams(forwardCookieParams);
                        }

                        if (this.debugEnabled)
                            log.debug(
                                    "DEBUG: Cookie Message 1 causes us to follow redirect to ["
                                            + newLocation
                                            + "]");

                        sendAndReceive(temp, false, false); // do NOT redirect.. handle it here

                        // handle any cookies set from following redirects that override the cookie
                        // set in the redirect itself (if any)
                        // note that this will handle the case where a latter cookie unsets one set
                        // earlier.
                        HtmlParameter cookieBack1Temp =
                                getResponseCookie(temp, currentHtmlParameter.getName());
                        if (cookieBack1Temp != null) {
                            cookieBack1 = cookieBack1Temp;
                            cookieBack1TimeReceived =
                                    System.currentTimeMillis(); // in ms.  record when we got the
                            // cookie.. in case it has a
                            // Max-Age directive
                        }

                        // reset the "final" version of message1 to use the final response in the
                        // chain
                        msg1Final = temp;
                    }
                    ///////////////////////////

                    // if non-200 on the final response for message 1, no point in continuing. Bale
                    // out.
                    if (!isPage200(msg1Final)) {
                        if (this.debugEnabled) {
                            log.debug(
                                    "Got a non-200 response when sending ["
                                            + msg1Initial.getRequestHeader().getURI()
                                            + "] with param ["
                                            + currentHtmlParameter.getName()
                                            + "] = NULL (possibly somewhere in the redirects)");
                        }
                        continue;
                    }

                    // now check that the response set a cookie. if it didn't, then either..
                    // 1) we are messing with the wrong field
                    // 2) the app doesn't do sessions
                    // either way, there is not much point in continuing to look at this field..

                    if (cookieBack1 == null || cookieBack1.getValue() == null) {
                        // no cookie was set, or the cookie param was set to a null value
                        if (this.debugEnabled)
                            log.debug(
                                    "The Cookie parameter was NOT set in the response, when cookie param ["
                                            + currentHtmlParameter.getName()
                                            + "] was set to NULL: "
                                            + cookieBack1);
                        continue;
                    }

                    //////////////////////////////////////////////////////////////////////
                    // at this point, before continuing to check for Session Fixation, do some other
                    // checks on the session cookie we got back
                    // that might cause us to raise additional alerts (in addition to doing the main
                    // check for Session Fixation)
                    //////////////////////////////////////////////////////////////////////

                    // Check 1: was the session cookie sent and received securely by the server?
                    // If not, alert this fact
                    if ((!msg1Final.getRequestHeader().isSecure())
                            || (!containsIgnoreCase(cookieBack1.getFlags(), "secure"))) {
                        // pass the original param value here, not the new value, since we're
                        // displaying the session id exposed in the original message
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidsentinsecurely.alert.extrainfo",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName(),
                                        currentHtmlParameter.getValue());
                        if (!cookieBack1.getFlags().contains("secure")) {
                            extraInfo +=
                                    ("\n"
                                            + Constant.messages.getString(
                                                    "ascanbeta.sessionidsentinsecurely.alert.extrainfo.secureflagnotset"));
                        }

                        // and figure out the risk, depending on whether it is a login page
                        int risk = Alert.RISK_LOW;
                        if (loginUrl) {
                            extraInfo +=
                                    ("\n"
                                            + Constant.messages.getString(
                                                    "ascanbeta.sessionidsentinsecurely.alert.extrainfo.loginpage"));
                            // login page, so higher risk
                            risk = Alert.RISK_MEDIUM;
                        } else {
                            // not a login page.. lower risk
                            risk = Alert.RISK_LOW;
                        }

                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidsentinsecurely.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());
                        String vulnname =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidsentinsecurely.name");
                        String vulndesc =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidsentinsecurely.desc");
                        String vulnsoln =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidsentinsecurely.soln");

                        // raise alert with some extra info, indicating that the alert is
                        // not specific to Session Fixation, but has its own title and description
                        // (etc.)
                        // the alert here is "Session id sent insecurely", or words to that effect.
                        newAlert()
                                .setRisk(risk)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(vulnname)
                                .setDescription(vulndesc)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setSolution(vulnsoln)
                                .setMessage(getBaseMsg())
                                .raise();

                        if (log.isDebugEnabled()) {
                            String logMessage =
                                    MessageFormat.format(
                                            "A session identifier in {2} field: [{3}] may be sent "
                                                    + "via an insecure mechanism at [{0}] URL [{1}]",
                                            getBaseMsg().getRequestHeader().getMethod(),
                                            getBaseMsg().getRequestHeader().getURI().getURI(),
                                            currentHtmlParameter.getType(),
                                            currentHtmlParameter.getName());
                            log.debug(logMessage);
                        }
                        // Note: do NOT continue to the next field at this point..
                        // since we still need to check for Session Fixation.
                    }

                    //////////////////////////////////////////////////////////////////////
                    // Check 2: is the session cookie that was set accessible to Javascript?
                    // If so, alert this fact too
                    if (!containsIgnoreCase(cookieBack1.getFlags(), "httponly") && loginUrl) {
                        // pass the original param value here, not the new value, since we're
                        // displaying the session id exposed in the original message
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidaccessiblebyjavascript.alert.extrainfo",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName(),
                                        currentHtmlParameter.getValue());
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidaccessiblebyjavascript.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());
                        String vulnname =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidaccessiblebyjavascript.name");
                        String vulndesc =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidaccessiblebyjavascript.desc");
                        String vulnsoln =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidaccessiblebyjavascript.soln");

                        extraInfo +=
                                ("\n"
                                        + Constant.messages.getString(
                                                "ascanbeta.sessionidaccessiblebyjavascript.alert.extrainfo.loginpage"));

                        // raise alert with some extra info, indicating that the alert is
                        // not specific to Session Fixation, but has its own title and description
                        // (etc.)
                        // the alert here is "Session id accessible in Javascript", or words to that
                        // effect.
                        newAlert()
                                .setRisk(Alert.RISK_LOW)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(vulnname)
                                .setDescription(vulndesc)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setSolution(vulnsoln)
                                .setMessage(getBaseMsg())
                                .raise();

                        if (log.isDebugEnabled()) {
                            String logMessage =
                                    MessageFormat.format(
                                            "A session identifier in [{0}] URL [{1}] {2} field: "
                                                    + "[{3}] may be accessible to JavaScript",
                                            getBaseMsg().getRequestHeader().getMethod(),
                                            getBaseMsg().getRequestHeader().getURI().getURI(),
                                            currentHtmlParameter.getType(),
                                            currentHtmlParameter.getName());
                            log.debug(logMessage);
                        }
                        // Note: do NOT continue to the next field at this point..
                        // since we still need to check for Session Fixation.
                    }

                    //////////////////////////////////////////////////////////////////////
                    // Check 3: is the session cookie set to expire soon? when the browser session
                    // closes? never?
                    // the longer the session cookie is valid, the greater the risk. alert it
                    // accordingly
                    String cookieBack1Expiry = null;
                    int sessionExpiryRiskLevel;
                    String sessionExpiryDescription = null;

                    // check for the Expires header
                    for (Iterator<String> i = cookieBack1.getFlags().iterator(); i.hasNext(); ) {
                        String cookieBack1Flag = i.next();
                        // if ( this.debugEnabled ) log.debug("Cookie back 1 flag (checking for
                        // Expires): "+ cookieBack1Flag);
                        // match in a case insensitive manner. never know what case various web
                        // servers are going to send back.
                        // if (cookieBack1Flag.matches("(?i)expires=.*")) {
                        if (cookieBack1Flag.toLowerCase(Locale.ENGLISH).startsWith("expires=")) {
                            String[] cookieBack1FlagValues = cookieBack1Flag.split("=");
                            if (cookieBack1FlagValues.length > 1) {
                                if (this.debugEnabled)
                                    log.debug("Cookie Expiry: " + cookieBack1FlagValues[1]);
                                cookieBack1Expiry = cookieBack1FlagValues[1]; // the Date String
                                sessionExpiryDescription =
                                        cookieBack1FlagValues[1]; // the Date String
                                cookieBack1ExpiryDate =
                                        DateUtil.parseDate(cookieBack1Expiry); // the actual Date
                            }
                        }
                    }

                    // also check for the Max-Age header, which overrides the Expires header.
                    // WARNING: this Directive is reported to be ignored by IE, so if both Expires
                    // and Max-Age are present
                    // and we report based on the Max-Age value, but the user is using IE, then the
                    // results reported
                    // by us here may be different from those actually experienced by the user! (we
                    // use Max-Age, IE uses Expires)
                    for (Iterator<String> i = cookieBack1.getFlags().iterator(); i.hasNext(); ) {
                        String cookieBack1Flag = i.next();
                        // if ( this.debugEnabled ) log.debug("Cookie back 1 flag (checking for
                        // Max-Age): "+ cookieBack1Flag);
                        // match in a case insensitive manner. never know what case various web
                        // servers are going to send back.
                        if (cookieBack1Flag.toLowerCase(Locale.ENGLISH).startsWith("max-age=")) {
                            String[] cookieBack1FlagValues = cookieBack1Flag.split("=");
                            if (cookieBack1FlagValues.length > 1) {
                                // now the Max-Age value is the number of seconds relative to the
                                // time the browser received the cookie
                                // (as stored in cookieBack1TimeReceived)
                                if (this.debugEnabled)
                                    log.debug("Cookie Max Age: " + cookieBack1FlagValues[1]);
                                long cookie1DropDeadMS =
                                        cookieBack1TimeReceived
                                                + (Long.parseLong(cookieBack1FlagValues[1]) * 1000);

                                cookieBack1ExpiryDate =
                                        new Date(cookie1DropDeadMS); // the actual Date the cookie
                                // expires (by Max-Age)
                                cookieBack1Expiry =
                                        DateUtil.formatDate(
                                                cookieBack1ExpiryDate, DateUtil.PATTERN_RFC1123);
                                sessionExpiryDescription =
                                        cookieBack1Expiry; // needs to the Date String
                            }
                        }
                    }
                    String sessionExpiryRiskDescription = null;
                    // check the Expiry/Max-Age details garnered (if any)

                    // and figure out the risk, depending on whether it is a login page
                    // and how long the session will live before expiring
                    if (cookieBack1ExpiryDate == null) {
                        // session expires when the browser closes.. rate this as medium risk?
                        sessionExpiryRiskLevel = Alert.RISK_MEDIUM;
                        sessionExpiryRiskDescription = "ascanbeta.sessionidexpiry.browserclose";
                        sessionExpiryDescription =
                                Constant.messages.getString(sessionExpiryRiskDescription);
                    } else {
                        long datediffSeconds =
                                (cookieBack1ExpiryDate.getTime() - cookieBack1TimeReceived) / 1000;
                        long anHourSeconds = 3600;
                        long aDaySeconds = anHourSeconds * 24;
                        long aWeekSeconds = aDaySeconds * 7;

                        if (datediffSeconds < 0) {
                            if (this.debugEnabled)
                                log.debug("The session cookie has expired already");
                            sessionExpiryRiskDescription = "ascanbeta.sessionidexpiry.timeexpired";
                            sessionExpiryRiskLevel =
                                    Alert.RISK_INFO; // no risk.. the cookie has expired already
                        } else if (datediffSeconds > aWeekSeconds) {
                            if (this.debugEnabled)
                                log.debug(
                                        "The session cookie is set to last for more than a week!");
                            sessionExpiryRiskDescription =
                                    "ascanbeta.sessionidexpiry.timemorethanoneweek";
                            sessionExpiryRiskLevel = Alert.RISK_HIGH;
                        } else if (datediffSeconds > aDaySeconds) {
                            if (this.debugEnabled)
                                log.debug("The session cookie is set to last for more than a day");
                            sessionExpiryRiskDescription =
                                    "ascanbeta.sessionidexpiry.timemorethanoneday";
                            sessionExpiryRiskLevel = Alert.RISK_MEDIUM;
                        } else if (datediffSeconds > anHourSeconds) {
                            if (this.debugEnabled)
                                log.debug(
                                        "The session cookie is set to last for more than an hour");
                            sessionExpiryRiskDescription =
                                    "ascanbeta.sessionidexpiry.timemorethanonehour";
                            sessionExpiryRiskLevel = Alert.RISK_LOW;
                        } else {
                            if (this.debugEnabled)
                                log.debug(
                                        "The session cookie is set to last for less than an hour!");
                            sessionExpiryRiskDescription =
                                    "ascanbeta.sessionidexpiry.timelessthanonehour";
                            sessionExpiryRiskLevel = Alert.RISK_INFO;
                        }
                    }

                    if (!loginUrl) {
                        // decrement the risk if it's not a login page
                        sessionExpiryRiskLevel--;
                    }

                    // alert it if the default session expiry risk level is more than informational
                    if (sessionExpiryRiskLevel > Alert.RISK_INFO) {
                        // pass the original param value here, not the new value
                        String cookieReceivedTime =
                                cookieBack1Expiry =
                                        DateUtil.formatDate(
                                                new Date(cookieBack1TimeReceived),
                                                DateUtil.PATTERN_RFC1123);
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidexpiry.alert.extrainfo",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName(),
                                        currentHtmlParameter.getValue(),
                                        sessionExpiryDescription,
                                        cookieReceivedTime);
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.sessionidexpiry.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());
                        String vulnname =
                                Constant.messages.getString("ascanbeta.sessionidexpiry.name");
                        String vulndesc =
                                Constant.messages.getString("ascanbeta.sessionidexpiry.desc");
                        String vulnsoln =
                                Constant.messages.getString("ascanbeta.sessionidexpiry.soln");
                        if (loginUrl) {
                            extraInfo +=
                                    ("\n"
                                            + Constant.messages.getString(
                                                    "ascanbeta.sessionidexpiry.alert.extrainfo.loginpage"));
                        }

                        // raise alert with some extra info, indicating that the alert is
                        // not specific to Session Fixation, but has its own title and description
                        // (etc.)
                        // the alert here is "Session Id Expiry Time is excessive", or words to that
                        // effect.
                        newAlert()
                                .setRisk(sessionExpiryRiskLevel)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(vulnname)
                                .setDescription(vulndesc)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setSolution(vulnsoln)
                                .setMessage(getBaseMsg())
                                .raise();

                        if (log.isDebugEnabled()) {
                            String logMessage =
                                    MessageFormat.format(
                                            "A session identifier in [{0}] URL [{1}] {2} field: "
                                                    + "[{3}] may be accessed until [{4}], unless the session is destroyed.",
                                            getBaseMsg().getRequestHeader().getMethod(),
                                            getBaseMsg().getRequestHeader().getURI().getURI(),
                                            currentHtmlParameter.getType(),
                                            currentHtmlParameter.getName(),
                                            sessionExpiryDescription);
                            log.debug(logMessage);
                        }
                        // Note: do NOT continue to the next field at this point..
                        // since we still need to check for Session Fixation.
                    }

                    if (!loginUrl) {
                        // not a login page.. skip
                        continue;
                    }

                    ////////////////////////////////////////////////////////////////////////////////////////////
                    /// Message 2 - processing starts here
                    ////////////////////////////////////////////////////////////////////////////////////////////
                    // so now that we know the URL responds with 200 (OK), and that it sets a
                    // cookie, lets re-issue the original request,
                    // but lets add in the new (valid) session cookie that was just issued.
                    // we will re-send it.  the aim is then to see if it accepts the cookie (BAD, in
                    // some circumstances),
                    // or if it issues a new session cookie (GOOD, in most circumstances)
                    if (this.debugEnabled)
                        log.debug(
                                "A Cookie was set by the URL for the correct param, when param ["
                                        + currentHtmlParameter.getName()
                                        + "] was set to NULL: "
                                        + cookieBack1);

                    // use a copy of msg2Initial, since it has already had the correct cookie
                    // removed in the request..
                    // do NOT use msg2Initial itself, as this will cause both requests in the GUI to
                    // show the modified data..
                    // finally send the second message, and see how it comes back.
                    HttpMessage msg2Initial = msg1Initial.cloneRequest();

                    TreeSet<HtmlParameter> cookieParams2Set =
                            msg2Initial.getRequestHeader().getCookieParams();
                    cookieParams2Set.add(cookieBack1);
                    msg2Initial.setCookieParams(cookieParams2Set);

                    // resend the copy of the initial message, but with the valid session cookie
                    // added in, to see if it is accepted
                    // do not automatically follow redirects, as we need to check these for cookies
                    // being set.
                    sendAndReceive(msg2Initial, false, false);

                    // create a copy of msg2Initial to play with to handle redirects (if any).
                    // we use a copy because if we change msg2Initial itself, it messes the URL and
                    // params displayed on the GUI.
                    HttpMessage temp2 = msg2Initial;
                    HttpMessage msg2Final = msg2Initial;
                    HtmlParameter cookieBack2Previous = cookieBack1;
                    HtmlParameter cookieBack2 =
                            getResponseCookie(msg2Initial, currentHtmlParameter.getName());

                    int redirectsFollowed2 = 0;
                    while (HttpStatusCode.isRedirection(
                            temp2.getResponseHeader().getStatusCode())) {

                        // clone the previous message
                        boolean secure2 = temp2.getRequestHeader().isSecure();
                        temp2 = temp2.cloneAll();

                        redirectsFollowed2++;
                        if (redirectsFollowed2 > 10) {
                            throw new Exception(
                                    "Too many redirects were specified in the second message");
                        }

                        // create a new URI from the absolute location returned, and interpret it as
                        // escaped
                        // note that the standard says that the Location returned should be
                        // absolute, but it ain't always so...
                        URI newLocation =
                                new URI(
                                        temp2.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                        true);

                        // and follow the forward url
                        // need to clear the params (which would come from the initial POST,
                        // otherwise)
                        temp2.getRequestHeader().setGetParams(new TreeSet<HtmlParameter>());
                        temp2.setRequestBody("");
                        temp2.setResponseBody(
                                ""); // make sure no values accidentally carry from one iteration to
                        // the next

                        try {
                            temp2.getRequestHeader().setURI(newLocation);
                        } catch (Exception e) {
                            // the Location field contents may not be standards compliant. Lets
                            // generate a uri to use as a workaround where a relative path was
                            // given instead of an absolute one
                            URI newLocationWorkaround =
                                    new URI(
                                            temp2.getRequestHeader().getURI(),
                                            temp2.getResponseHeader()
                                                    .getHeader(HttpHeader.LOCATION),
                                            true);

                            // try again, except this time, if it fails, don't try to handle it
                            if (this.debugEnabled)
                                log.debug(
                                        "The Location ["
                                                + newLocation
                                                + "] specified in a redirect was not valid. Trying workaround url ["
                                                + newLocationWorkaround
                                                + "]");
                            temp2.getRequestHeader().setURI(newLocationWorkaround);
                        }
                        temp2.getRequestHeader().setSecure(secure2);
                        temp2.getRequestHeader().setMethod(HttpRequestHeader.GET);
                        temp2.getRequestHeader()
                                .setContentLength(
                                        0); // since we send a GET, the body will be 0 long
                        if (cookieBack2 != null) {
                            // if the previous request sent back a cookie, we need to set that
                            // cookie when following redirects, as a browser would
                            // also make sure to delete the previous value set for the cookie value
                            if (this.debugEnabled) {
                                log.debug(
                                        "Deleting old cookie ["
                                                + cookieBack2Previous
                                                + "], and adding in cookie ["
                                                + cookieBack2
                                                + "] for a redirect");
                            }
                            TreeSet<HtmlParameter> forwardCookieParams =
                                    temp2.getRequestHeader().getCookieParams();
                            forwardCookieParams.remove(cookieBack2Previous);
                            forwardCookieParams.add(cookieBack2);
                            temp2.getRequestHeader().setCookieParams(forwardCookieParams);
                        }

                        sendAndReceive(
                                temp2, false,
                                false); // do NOT automatically redirect.. handle redirects here

                        // handle any cookies set from following redirects that override the cookie
                        // set in the redirect itself (if any)
                        // note that this will handle the case where a latter cookie unsets one set
                        // earlier.
                        HtmlParameter cookieBack2Temp =
                                getResponseCookie(temp2, currentHtmlParameter.getName());
                        if (cookieBack2Temp != null) {
                            cookieBack2Previous = cookieBack2;
                            cookieBack2 = cookieBack2Temp;
                        }

                        // reset the "final" version of message2 to use the final response in the
                        // chain
                        msg2Final = temp2;
                    }
                    if (this.debugEnabled) log.debug("Done following redirects");

                    // final result was non-200, no point in continuing. Bale out.
                    if (!isPage200(msg2Final)) {
                        if (this.debugEnabled)
                            log.debug(
                                    "Got a non-200 response when sending ["
                                            + msg2Initial.getRequestHeader().getURI()
                                            + "] with a borrowed cookie (or by following a redirect) for param ["
                                            + currentHtmlParameter.getName()
                                            + "]");
                        continue; // to next parameter
                    }

                    // and what we've been waiting for.. do we get a *different* cookie being set in
                    // the response of message 2??
                    // or do we get a new cookie back at all?
                    // No cookie back => the borrowed cookie was accepted. Not ideal
                    // Cookie back, but same as the one we sent in => the borrowed cookie was
                    // accepted. Not ideal
                    if ((cookieBack2 == null)
                            || cookieBack2.getValue().equals(cookieBack1.getValue())) {
                        // no cookie back, when a borrowed cookie is in use.. suspicious!

                        // use the cookie extrainfo message, which is specific to the case of
                        // cookies
                        // pretty much everything else is generic to all types of Session Fixation
                        // vulnerabilities
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.sessionfixation.alert.cookie.extrainfo",
                                        currentHtmlParameter.getName(),
                                        cookieBack1.getValue(),
                                        (cookieBack2 == null ? "NULL" : cookieBack2.getValue()));
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.sessionfixation.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());

                        if (loginUrl) {
                            extraInfo +=
                                    ("\n"
                                            + Constant.messages.getString(
                                                    "ascanbeta.sessionfixation.alert.cookie.extrainfo.loginpage"));
                        }

                        newAlert()
                                .setRisk(Alert.RISK_INFO)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setMessage(msg2Initial)
                                .raise();
                        logSessionFixation(
                                msg2Initial,
                                currentHtmlParameter.getType().toString(),
                                currentHtmlParameter.getName());
                    }

                    continue; // jump to the next iteration of the loop (ie, the next parameter)
                } // end of the cookie code.

                // start of the url parameter code
                // note that this actually caters for
                // - actual URL parameters
                // - pseudo URL parameters, where the sessionid was in the path portion of the URL,
                // in conjunction with URL re-writing
                if (currentHtmlParameter.getType().equals(HtmlParameter.Type.url)) {
                    boolean isPseudoUrlParameter =
                            false; // is this "url parameter" actually a url parameter, or was it
                    // path of the path (+url re-writing)?
                    String possibleSessionIdIssuedForUrlParam = null;
                    // remove the named url parameter from the request..
                    TreeSet<HtmlParameter> urlRequestParams =
                            msg1Initial.getUrlParams(); // get parameters?
                    if (!urlRequestParams.remove(currentHtmlParameter)) {
                        isPseudoUrlParameter = true;
                        // was not removed because it was a pseudo Url parameter, not a real url
                        // parameter.. (so it would not be in the url params)
                        // in this case, we will need to "rewrite" (i.e. hack) the URL path to
                        // remove
                        // the pseudo url parameter portion
                        // ie, we need to remove the ";jsessionid=<sessionid>" bit from the path
                        // (assuming the current field is named 'jsessionid')
                        // and replace it with ";jsessionid=" (ie, we nullify the possible "session"
                        // parameter in the hope that a new session will be issued)
                        // then we continue as usual to see if the URL is vulnerable to a Session
                        // Fixation issue
                        // Side note: quote the string to search for, and the replacement, so that
                        // regex special characters are treated as literals
                        String hackedUrl =
                                requestUrl.replaceAll(
                                        Pattern.quote(
                                                ";"
                                                        + currentHtmlParameter.getName()
                                                        + "="
                                                        + currentHtmlParameter.getValue()),
                                        Matcher.quoteReplacement(
                                                ";" + currentHtmlParameter.getName() + "="));
                        if (this.debugEnabled)
                            log.debug(
                                    "Removing the pseudo URL parameter from ["
                                            + requestUrl
                                            + "]: ["
                                            + hackedUrl
                                            + "]");
                        // Note: the URL is not escaped. Handle it.
                        msg1Initial.getRequestHeader().setURI(new URI(hackedUrl, false));
                    }
                    msg1Initial.setGetParams(urlRequestParams); // url parameters

                    // send the message, minus the value for the current parameter, and see how it
                    // comes back.
                    // Note: automatically follow redirects.. no need to look at any intermediate
                    // responses.
                    // this was only necessary for cookie-based session implementations
                    sendAndReceive(msg1Initial);

                    // if non-200 on the response for message 1, no point in continuing. Bale out.
                    if (!isPage200(msg1Initial)) {
                        if (this.debugEnabled)
                            log.debug(
                                    "Got a non-200 response when sending ["
                                            + msg1Initial.getRequestHeader().getURI()
                                            + "] with param ["
                                            + currentHtmlParameter.getName()
                                            + "] = NULL (possibly somewhere in the redirects)");
                        continue;
                    }

                    // now parse the HTML response for urls that contain the same parameter name,
                    // and look at the values for that parameter
                    // if no values are found for the parameter, then
                    // 1) we are messing with the wrong field, or
                    // 2) the app doesn't do sessions
                    // either way, there is not much point in continuing to look at this field..

                    // parse out links in HTML (assume for a moment that all the URLs are in links)
                    // this gives us a map of parameter value for the current parameter, to the
                    // number of times it was encountered in links in the HTML
                    SortedMap<String, Integer> parametersInHTMLURls =
                            getParameterValueCountInHtml(
                                    msg1Initial.getResponseBody().toString(),
                                    currentHtmlParameter.getName(),
                                    isPseudoUrlParameter);
                    if (this.debugEnabled)
                        log.debug(
                                "The count of the various values of the ["
                                        + currentHtmlParameter.getName()
                                        + "] parameters in urls in the result of retrieving the url with a null value for parameter ["
                                        + currentHtmlParameter.getName()
                                        + "]: "
                                        + parametersInHTMLURls);

                    if (parametersInHTMLURls.isEmpty()) {
                        // setting the param to NULL did not cause any new values to be generated
                        // for it in the output..
                        // so either..
                        // it is not a session field, or
                        // it is a session field, but a session is only issued on authentication,
                        // and this is not an authentication url
                        // the app doesn't do sessions (etc.)
                        // either way, the parameter/url combo is not vulnerable, so continue with
                        // the next parameter
                        if (this.debugEnabled)
                            log.debug(
                                    "The URL parameter ["
                                            + currentHtmlParameter.getName()
                                            + "] was NOT set in any links in the response, when "
                                            + (isPseudoUrlParameter ? "pseudo/URL rewritten" : "")
                                            + " URL param ["
                                            + currentHtmlParameter.getName()
                                            + "] was set to NULL in the request, so it is likely not a session id field");
                        continue; // to the next parameter
                    } else if (parametersInHTMLURls.size() == 1) {
                        // the parameter was set to just one value in the output
                        // so it's quite possible it is the session id field that we have been
                        // looking for
                        // caveat 1: check it is longer than 3 chars long, to remove false
                        // positives..
                        // we assume here that a real session id will always be greater than 3
                        // characters long
                        // caveat 2: the value we got back for the param must be different from the
                        // value we
                        // over-wrote with NULL (empty) in the first place, otherwise it is very
                        // unlikely to
                        // be a session id field
                        possibleSessionIdIssuedForUrlParam = parametersInHTMLURls.firstKey();
                        // did we get back the same value we just nulled out in the original
                        // request?
                        // if so, use this to eliminate false positives, and to optimise.
                        if (possibleSessionIdIssuedForUrlParam.equals(
                                currentHtmlParameter.getValue())) {
                            if (this.debugEnabled)
                                log.debug(
                                        (isPseudoUrlParameter ? "pseudo/URL rewritten" : "")
                                                + " URL param ["
                                                + currentHtmlParameter.getName()
                                                + "], when set to NULL, causes 1 distinct values to be set for it in URLs in the output, but the possible session id value ["
                                                + possibleSessionIdIssuedForUrlParam
                                                + "] is the same as the value we over-wrote with NULL. 'Sorry, kid. You got the gift, but it looks like you're waiting for something'");
                            continue; // to the next parameter
                        }
                        if (possibleSessionIdIssuedForUrlParam.length() > 3) {
                            // raise an alert here on an exposed session id, even if it is not
                            // subject to a session fixation vulnerability
                            // log.info("The URL parameter ["+ currentHtmlParameter.getName() + "]
                            // was set ["+
                            // parametersInHTMLURls.get(possibleSessionIdIssuedForUrlParam)+ "]
                            // times to ["+ possibleSessionIdIssuedForUrlParam + "] in links in the
                            // response, when "+ (isPseudoUrlParameter?"pseudo/URL rewritten":"")+ "
                            // URL param ["+ currentHtmlParameter.getName() + "] was set to NULL in
                            // the request. This likely indicates it is a session id field.");

                            // pass the original param value here, not the new value, since we're
                            // displaying the session id exposed in the original message
                            String extraInfo =
                                    Constant.messages.getString(
                                            "ascanbeta.sessionidexposedinurl.alert.extrainfo",
                                            currentHtmlParameter.getType(),
                                            currentHtmlParameter.getName(),
                                            currentHtmlParameter.getValue());
                            String attack =
                                    Constant.messages.getString(
                                            "ascanbeta.sessionidexposedinurl.alert.attack",
                                            (isPseudoUrlParameter ? "pseudo/URL rewritten " : "")
                                                    + currentHtmlParameter.getType(),
                                            currentHtmlParameter.getName());
                            String vulnname =
                                    Constant.messages.getString(
                                            "ascanbeta.sessionidexposedinurl.name");
                            String vulndesc =
                                    Constant.messages.getString(
                                            "ascanbeta.sessionidexposedinurl.desc");
                            String vulnsoln =
                                    Constant.messages.getString(
                                            "ascanbeta.sessionidexposedinurl.soln");

                            if (loginUrl) {
                                extraInfo +=
                                        ("\n"
                                                + Constant.messages.getString(
                                                        "ascanbeta.sessionidexposedinurl.alert.extrainfo.loginpage"));
                            }

                            // call bingo with some extra info, indicating that the alert is
                            // not specific to Session Fixation, but has its own title and
                            // description (etc.)
                            // the alert here is "Session id exposed in url", or words to that
                            // effect.
                            newAlert()
                                    .setRisk(Alert.RISK_MEDIUM)
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setName(vulnname)
                                    .setDescription(vulndesc)
                                    .setParam(currentHtmlParameter.getName())
                                    .setAttack(attack)
                                    .setOtherInfo(extraInfo)
                                    .setSolution(vulnsoln)
                                    .setMessage(getBaseMsg())
                                    .raise();

                            if (log.isDebugEnabled()) {
                                String logMessage =
                                        MessageFormat.format(
                                                "An exposed session identifier has been found at "
                                                        + "[{0}] URL [{1}] on {2} field: [{3}]",
                                                getBaseMsg().getRequestHeader().getMethod(),
                                                getBaseMsg().getRequestHeader().getURI().getURI(),
                                                (isPseudoUrlParameter ? "pseudo " : "")
                                                        + currentHtmlParameter.getType(),
                                                currentHtmlParameter.getName());
                                log.debug(logMessage);
                            }
                            // Note: do NOT continue to the next field at this point..
                            // since we still need to check for Session Fixation.
                        } else {
                            if (this.debugEnabled)
                                log.debug(
                                        (isPseudoUrlParameter ? "pseudo/URL rewritten" : "")
                                                + " URL param ["
                                                + currentHtmlParameter.getName()
                                                + "], when set to NULL, causes 1 distinct values to be set for it in URLs in the output, but the possible session id value ["
                                                + possibleSessionIdIssuedForUrlParam
                                                + "] is too short to be a real session id.");
                            continue; // to the next parameter
                        }
                    } else {
                        // strange scenario: setting the param to null causes multiple different
                        // values to be set for it in the output
                        // it could still be a session parameter, but we assume it is *not* a
                        // session id field
                        // log it, but assume it is not a session id
                        if (this.debugEnabled)
                            log.debug(
                                    (isPseudoUrlParameter ? "pseudo/URL rewritten" : "")
                                            + " URL param ["
                                            + currentHtmlParameter.getName()
                                            + "], when set to NULL, causes ["
                                            + parametersInHTMLURls.size()
                                            + "] distinct values to be set for it in URLs in the output. Assuming it is NOT a session id as a consequence. This could be a false negative");
                        continue; // to the next parameter
                    }

                    ////////////////////////////////////////////////////////////////////////////////////////////
                    /// Message 2 - processing starts here
                    ////////////////////////////////////////////////////////////////////////////////////////////
                    // we now have a plausible session id field to play with, so set it to a
                    // borrowed value.
                    // ie: lets re-send the request, but add in the new (valid) session value that
                    // was just issued.
                    // the aim is then to see if it accepts the session without re-issuing the
                    // session id (BAD, in some circumstances),
                    // or if it issues a new session value (GOOD, in most circumstances)

                    // and set the (modified) session for the second message
                    // use a copy of msg2Initial, since it has already had the correct session
                    // removed in the request..
                    // do NOT use msg2Initial itself, as this will cause both requests in the GUI to
                    // show the modified data..
                    // finally send the second message, and see how it comes back.
                    HttpMessage msg2Initial = msg1Initial.cloneRequest();

                    // set the parameter to the new session id value (in different manners,
                    // depending on whether it is a real url param, or a pseudo url param)
                    if (isPseudoUrlParameter) {
                        // we need to "rewrite" (hack) the URL path to remove the pseudo url
                        // parameter portion
                        // id, we need to remove the ";jsessionid=<sessionid>" bit from the path
                        // and replace it with ";jsessionid=" (ie, we nullify the possible "session"
                        // parameter in the hope that a new session will be issued)
                        // then we continue as usual to see if the URL is vulnerable to a Session
                        // Fixation issue
                        // Side note: quote the string to search for, and the replacement, so that
                        // regex special characters are treated as literals
                        String hackedUrl =
                                requestUrl.replaceAll(
                                        Pattern.quote(
                                                ";"
                                                        + currentHtmlParameter.getName()
                                                        + "="
                                                        + currentHtmlParameter.getValue()),
                                        Matcher.quoteReplacement(
                                                ";"
                                                        + currentHtmlParameter.getName()
                                                        + "="
                                                        + possibleSessionIdIssuedForUrlParam));
                        if (this.debugEnabled)
                            log.debug(
                                    "Changing the pseudo URL parameter from ["
                                            + requestUrl
                                            + "]: ["
                                            + hackedUrl
                                            + "]");
                        // Note: the URL is not escaped
                        msg2Initial.getRequestHeader().setURI(new URI(hackedUrl, false));
                        msg2Initial.setGetParams(
                                msg1Initial.getUrlParams()); // restore the GET params
                    } else {
                        // do it via the normal url parameters
                        TreeSet<HtmlParameter> urlRequestParams2 = msg2Initial.getUrlParams();
                        urlRequestParams2.add(
                                new HtmlParameter(
                                        Type.url,
                                        currentHtmlParameter.getName(),
                                        possibleSessionIdIssuedForUrlParam));
                        msg2Initial.setGetParams(urlRequestParams2); // restore the GET params
                    }

                    // resend a copy of the initial message, but with the new valid session
                    // parameter added in, to see if it is accepted
                    // automatically follow redirects, which are irrelevant for the purposes of
                    // testing URL parameters
                    sendAndReceive(msg2Initial);

                    // final result was non-200, no point in continuing. Bale out.
                    if (!isPage200(msg2Initial)) {
                        if (this.debugEnabled)
                            log.debug(
                                    "Got a non-200 response when sending ["
                                            + msg2Initial.getRequestHeader().getURI()
                                            + "] with a borrowed session (or by following a redirect) for param ["
                                            + currentHtmlParameter.getName()
                                            + "]");
                        continue; // next field!
                    }

                    // do the analysis on the parameters in link urls in the HTML output again to
                    // see if the session id was regenerated
                    SortedMap<String, Integer> parametersInHTMLURls2 =
                            getParameterValueCountInHtml(
                                    msg2Initial.getResponseBody().toString(),
                                    currentHtmlParameter.getName(),
                                    isPseudoUrlParameter);
                    if (this.debugEnabled)
                        log.debug(
                                "The count of the various values of the ["
                                        + currentHtmlParameter.getName()
                                        + "] parameters in urls in the result of retrieving the url with a borrowed session value for parameter ["
                                        + currentHtmlParameter.getName()
                                        + "]: "
                                        + parametersInHTMLURls2);

                    if (parametersInHTMLURls2.size() != 1) {
                        // either no values, or multiple values, but not 1 value.  For a session
                        // that was regenerated, we would have expected to see
                        // just 1 new value
                        if (this.debugEnabled)
                            log.debug(
                                    "The HTML has spoken. ["
                                            + currentHtmlParameter.getName()
                                            + "] doesn't look like a session id field, because there are "
                                            + parametersInHTMLURls2.size()
                                            + " distinct values for this parameter in urls in the HTML output");
                        continue;
                    }
                    // there is but one value for this param in links in the HTML output. But is it
                    // vulnerable to Session Fixation? Ie, is it the same parameter?
                    String possibleSessionIdIssuedForUrlParam2 = parametersInHTMLURls2.firstKey();
                    if (possibleSessionIdIssuedForUrlParam2.equals(
                            possibleSessionIdIssuedForUrlParam)) {
                        // same sessionid used in the output.. so it is likely that we have a
                        // Session Fixation issue..

                        // use the url param extrainfo message, which is specific to the case of url
                        // parameters and url re-writing Session Fixation issue
                        // pretty much everything else is generic to all types of Session Fixation
                        // vulnerabilities
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.sessionfixation.alert.url.extrainfo",
                                        currentHtmlParameter.getName(),
                                        possibleSessionIdIssuedForUrlParam,
                                        possibleSessionIdIssuedForUrlParam2);
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.sessionfixation.alert.attack",
                                        (isPseudoUrlParameter ? "pseudo/URL rewritten " : "")
                                                + currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());

                        int risk = Alert.RISK_LOW;
                        if (loginUrl) {
                            extraInfo +=
                                    ("\n"
                                            + Constant.messages.getString(
                                                    "ascanbeta.sessionfixation.alert.url.extrainfo.loginpage"));
                            // login page, so higher risk
                            risk = Alert.RISK_MEDIUM;
                        } else {
                            // not a login page.. lower risk
                            risk = Alert.RISK_LOW;
                        }

                        newAlert()
                                .setRisk(risk)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setMessage(getBaseMsg())
                                .raise();
                        logSessionFixation(
                                getBaseMsg(),
                                (isPseudoUrlParameter ? "pseudo " : "")
                                        + currentHtmlParameter.getType(),
                                currentHtmlParameter.getName());

                        continue; // jump to the next iteration of the loop (ie, the next parameter)

                    } else {
                        // different sessionid used in the output.. so it is unlikely that we have a
                        // Session Fixation issue..
                        // more likely that the Session is being re-issued for every single request,
                        // or we have issues a login request, which
                        // normally causes a session to be reissued
                        if (this.debugEnabled)
                            log.debug(
                                    "The "
                                            + (isPseudoUrlParameter ? "pseudo/URL rewritten" : "")
                                            + " parameter ["
                                            + currentHtmlParameter.getName()
                                            + "] in url ["
                                            + getBaseMsg().getRequestHeader().getMethod()
                                            + "] ["
                                            + getBaseMsg().getRequestHeader().getURI()
                                            + "] changes with requests, and so it likely not vulnerable to Session Fixation");
                    }

                    continue; // onto the next parameter
                } // end of the url parameter code.
            } // end of the for loop around the parameter list

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.error("An error occurred checking a url for Session Fixation issues", e);
        }
    }

    private static void logSessionFixation(
            HttpMessage msg, String parameterType, String parameterName) {
        if (!log.isDebugEnabled()) {
            return;
        }

        String logMessage =
                MessageFormat.format(
                        "A likely Session Fixation Vulnerability has been found with [{0}] URL [{1}] on {2} field: [{3}]",
                        msg.getRequestHeader().getMethod(),
                        msg.getRequestHeader().getURI(),
                        parameterType,
                        parameterName);
        log.debug(logMessage);
    }

    /**
     * finds and returns the cookie matching the specified cookie name from the message response.
     *
     * @param message
     * @param cookieName
     * @return the HtmlParameter representing the cookie, or null if no matching cookie was found
     */
    private HtmlParameter getResponseCookie(HttpMessage message, String cookieName) {
        TreeSet<HtmlParameter> cookieBackParams = message.getResponseHeader().getCookieParams();
        if (cookieBackParams.size() == 0) {
            // no cookies
            return null;
        }
        for (Iterator<HtmlParameter> i = cookieBackParams.iterator(); i.hasNext(); ) {
            HtmlParameter tempparam = i.next();
            if (tempparam.getName().equals(cookieName)) {
                // found it. return it.
                return tempparam;
            }
        }
        // there were cookies, but none matching the name
        return null;
    }

    /**
     * returns a SortedMap of the count for the various values of the parameter specified, as found
     * in links in the HTML
     *
     * @param html the HTML containing links to be parsed
     * @param parametername the parameter to look for in links in the HTML
     * @param pseudoUrlParameter is the parameter contained in the url itself, and processed using
     *     URL rewriting?
     * @return
     */
    private SortedMap<String, Integer> getParameterValueCountInHtml(
            String html, String parametername, boolean pseudoUrlParameter) throws Exception {
        TreeMap<String, Integer> parametersInHTMLURls = new TreeMap<>();
        Source source = new Source(html);
        // for now, just look at the HREF attribue in <a> tags (ie, in links in the HTML output)
        List<Element> elementList = source.getAllElements(HTMLElementName.A);
        for (Element element : elementList) {
            if (element.getAttributes() != null) {
                String urlInResults = element.getAttributeValue("href");
                if (this.debugEnabled)
                    log.debug(
                            "A HREF in the HTML results of request with NULL value for parameter ["
                                    + parametername
                                    + "]: "
                                    + urlInResults);
                if (urlInResults != null) {
                    // now parse out and count the value of the url parm with the name:
                    // currentHtmlParameter.getName()

                    // depending on the type of url parameter, get the parameters set in the output
                    // by one of two mechanisms
                    Set<HtmlParameter> urlParams = null;
                    // it is a regular url parameter,so look at the regular url parameters in the
                    // links in the output
                    if (pseudoUrlParameter) {
                        urlParams = getPseudoUrlParameters(urlInResults);
                        if (this.debugEnabled)
                            log.debug(
                                    "Pseudo url params of Link URL ["
                                            + urlInResults
                                            + "] : ["
                                            + urlParams
                                            + "]");
                    } else {
                        HttpMessage messageUrlInResults = null;
                        try {
                            messageUrlInResults = new HttpMessage(new URI(urlInResults, false));
                        } catch (HttpMalformedHeaderException e) {
                            // the url is in the href is likely not valid. skip to the nexe one.
                            if (this.debugEnabled)
                                log.debug(
                                        "URL ["
                                                + urlInResults
                                                + "] found in HTML results does not seem to be valid, and cannot be analysed for session ids. Skipping it.");
                            continue;
                        }
                        urlParams = messageUrlInResults.getUrlParams();
                    }

                    // now aggregate the param values by value, counting how many times we see each
                    // value.
                    for (Iterator<HtmlParameter> iterParamsInHRef = urlParams.iterator();
                            iterParamsInHRef.hasNext(); ) {
                        HtmlParameter urlParameter = iterParamsInHRef.next();
                        // if this parameter of the url returned matches the parameter name we are
                        // playing with
                        // record the value (and the number of instances in total found)
                        if (urlParameter.getName().equals(parametername)) {
                            // if (this.debugEnabled) log.debug("Found a match for the parameter
                            // ["+currentHtmlParameter.getName() +"] in a url in the results:
                            // "+urlParameter.getValue());
                            Integer parameterValueCount =
                                    parametersInHTMLURls.get(urlParameter.getValue());
                            if (parameterValueCount == null) {
                                parameterValueCount = Integer.valueOf(0);
                            }
                            // increment the count for this particular value of the parameter and
                            // store it
                            parameterValueCount = parameterValueCount.intValue() + 1;
                            parametersInHTMLURls.put(urlParameter.getValue(), parameterValueCount);
                        }
                    }
                }
            }
        }
        // we're outta here for the current url
        return parametersInHTMLURls;
    }

    /**
     * returns a Set of HtmlParameters (of type url) corresponding to pseudo URL parameters in the
     * url
     *
     * @param url the url to parse for pseudo url parameters
     * @return a Set of HtmlParameters
     */
    Set<HtmlParameter> getPseudoUrlParameters(String url) {

        TreeSet<HtmlParameter> pseudoUrlParams = new TreeSet<>();
        String[] urlBreakdown =
                url.split(
                        "\\?"); // do this to get rid of parameters.. we just want the path (but we
        // can live with the scheme, host, port, etc.)

        String[] pseudoUrlParamNames = urlBreakdown[0].split(";");
        // start with the bit *after* the first ";", ie, start with i = 1
        for (int i = 1; i < pseudoUrlParamNames.length; i++) {
            // parse out the possible pseudo url parameters into x=y
            String[] pseudoUrlParamKeyValue = pseudoUrlParamNames[i].split("=");
            if (pseudoUrlParamKeyValue.length
                    == 2) { // x=y should break into 2 parts.. no more, no less
                if (this.debugEnabled)
                    log.debug(
                            "Pseudo url arguments: ["
                                    + pseudoUrlParamKeyValue[0]
                                    + "]= ["
                                    + pseudoUrlParamKeyValue[1]
                                    + "]");
                // store it
                pseudoUrlParams.add(
                        new HtmlParameter(
                                Type.url, pseudoUrlParamKeyValue[0], pseudoUrlParamKeyValue[1]));
            }
        }
        // return them
        return pseudoUrlParams;
    }

    private static boolean containsIgnoreCase(Set<String> setToCheck, String strToFind) {
        for (String item : setToCheck) {
            if (item.equalsIgnoreCase(strToFind)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 384;
    }

    @Override
    public int getWascId() {
        return 37;
    }
}
