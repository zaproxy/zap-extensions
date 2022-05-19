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

import difflib.Delta;
import difflib.DiffUtils;
import difflib.Patch;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.HirshbergMatcher;

/**
 * The UsernameEnumerationScanRule identifies vulnerabilities with the login page or "forgot
 * password" page. It identifies urls where the page results depend on whether the username supplied
 * is valid or invalid using a differentiation based approach
 *
 * <p>TODO: how to avoid false positives on the password field?
 *
 * @author 70pointer
 */
public class UsernameEnumerationScanRule extends AbstractAppPlugin {

    private static final Logger LOG = LogManager.getLogger(UsernameEnumerationScanRule.class);

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION);

    private static ExtensionAuthentication extAuth =
            (ExtensionAuthentication)
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAuthentication.NAME);

    @Override
    public int getId() {
        return 40023;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.usernameenumeration.refs");
    }

    @Override
    public void init() {
        LOG.debug("Initialising");

        if (!shouldContinue(extAuth.getModel().getSession().getContexts())) {
            LOG.info(
                    "There does not appear to be any configured contexts using Form-based Authentication. Further attempts during the current scan will be skipped.");
            this.getParent().pluginSkipped(this);
        }
    }

    /**
     * looks for username enumeration in the login page, by changing the username field to be a
     * valid / invalid user, and looking for differences in the response
     */
    @Override
    public void scan() {

        // the technique to determine if usernames can be enumerated is as follows, using a variant
        // of the Freiling+Schinzel method,
        // adapted to the case where we do not know which is the username field
        //
        // 1) Request the original URL n times. (The original URL is assumed to have a valid
        // username, if not a valid password). Store the results in A[].
        // 2) Compute the longest common subsequence (LCS) of A[] into LCS_A
        // 3) for each parameter in the original URL (ie, for URL params, form params, and cookie
        // params)
        //	4) Change the current parameter (which we assume is the username parameter) to an invalid
        // username (randomly), and request the URL n times. Store the results in B[].
        //	5) Compute the longest common subsequence (LCS) of B[] into LCS_B
        //	6) If LCS_A <> LCS_B, then there is a Username Enumeration issue on the current parameter

        try {
            boolean loginUrl = false;

            // Are we dealing with a login url in any of the contexts of which this uri is part
            URI requestUri = getBaseMsg().getRequestHeader().getURI();

            List<Context> contextList =
                    extAuth.getModel().getSession().getContextsForUrl(requestUri.toString());

            // now loop, and see if the url is a login url in each of the contexts in turn...
            for (Context context : contextList) {
                URI loginUri = extAuth.getLoginRequestURIForContext(context);
                if (loginUri != null
                        && requestUri.getScheme().equals(loginUri.getScheme())
                        && requestUri.getHost().equals(loginUri.getHost())
                        && requestUri.getPort() == loginUri.getPort()
                        && requestUri.getPath().equals(loginUri.getPath())) {
                    // we got this far.. only the method (GET/POST), user details, query params,
                    // fragment, and POST params are possibly different from the login page.
                    loginUrl = true;
                    LOG.info(
                            "{} falls within a context, and is the defined Login URL. Scanning for possible Username Enumeration vulnerability.",
                            requestUri);
                    break;
                }
            }

            if (!loginUrl) {
                LOG.debug("{} is not a defined Login URL.", requestUri);
                return; // No need to continue for this URL
            }

            // find all params set in the request (GET/POST/Cookie)
            TreeSet<HtmlParameter> htmlParams = new TreeSet<>();
            htmlParams.addAll(getBaseMsg().getRequestHeader().getCookieParams());
            htmlParams.addAll(getBaseMsg().getFormParams());
            htmlParams.addAll(getBaseMsg().getUrlParams());

            int numberOfRequests = 0;
            if (this.getAttackStrength() == AttackStrength.INSANE) {
                numberOfRequests = 50;
            } else if (this.getAttackStrength() == AttackStrength.HIGH) {
                numberOfRequests = 15;
            } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
                numberOfRequests = 5;
            } else if (this.getAttackStrength() == AttackStrength.LOW) {
                numberOfRequests = 3;
            }

            // 1) Request the original URL n times. (The original URL is assumed to have a valid
            // username, if not a valid password). Store the results in A[].
            // make sure to manually handle all redirects, and cookies that may be set in response.
            // allocate enough space for the responses

            StringBuilder responseA = null;
            StringBuilder responseB = null;
            String longestCommonSubstringA = null;
            String longestCommonSubstringB = null;

            for (int i = 0; i < numberOfRequests; i++) {

                responseA = new StringBuilder(250);

                HttpMessage msgCpy = getNewMsg(); // clone the request, but not the response

                sendAndReceive(
                        msgCpy, false,
                        false); // request the URL, but do not automatically follow redirects.

                // get all cookies set in the response
                TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();

                int redirectCount = 0;
                while (HttpStatusCode.isRedirection(msgCpy.getResponseHeader().getStatusCode())) {
                    redirectCount++;

                    LOG.debug(
                            "Following redirect {} for message {} of {} iterations of the original query",
                            redirectCount,
                            i,
                            numberOfRequests);

                    // append the response to the responses so far for this particular instance
                    // this will give us a complete picture of the full set of actual traffic
                    // associated with following redirects for the request
                    responseA.append(msgCpy.getResponseHeader().getHeadersAsString());
                    responseA.append(msgCpy.getResponseBody().toString());

                    // and manually follow the redirect
                    // create a new message from scratch
                    HttpMessage msgRedirect = new HttpMessage();

                    // create a new URI from the absolute location returned, and interpret it as
                    // escaped
                    // note that the standard says that the Location returned should be absolute,
                    // but it ain't always so...
                    URI newLocation =
                            new URI(
                                    msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                    true);
                    try {
                        msgRedirect.getRequestHeader().setURI(newLocation);
                    } catch (Exception e) {
                        // the Location field contents may not be standards compliant. Lets generate
                        // a uri to use as a workaround where a relative path was
                        // given instead of an absolute one
                        URI newLocationWorkaround =
                                new URI(
                                        msgCpy.getRequestHeader().getURI(),
                                        msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                        true);
                        // try again, except this time, if it fails, don't try to handle it
                        LOG.debug(
                                "The Location [{}] specified in a redirect was not valid (not absolute?). Trying absolute workaround url [{}]",
                                newLocation,
                                newLocationWorkaround);
                        msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
                    }
                    msgRedirect
                            .getRequestHeader()
                            .setMethod(HttpRequestHeader.GET); // it's always a GET for a redirect
                    msgRedirect
                            .getRequestHeader()
                            .setContentLength(0); // since we send a GET, the body will be 0 long
                    if (!cookies.isEmpty()) {
                        // if a previous request sent back a cookie that has not since been
                        // invalidated, we need to set that cookie when following redirects, as a
                        // browser would
                        msgRedirect.getRequestHeader().setCookieParams(cookies);
                    }

                    LOG.debug("DEBUG: Following redirect to [{}]", newLocation);
                    sendAndReceive(msgRedirect, false, false); // do NOT redirect.. handle it here

                    // handle scenario where a cookie is unset in a subsequent iteration, or where
                    // the same cookie name is later re-assigned a different value
                    // ie, in these cases, do not simply (and dumbly) accumulate cookie detritus.
                    // first get all cookies set in the response
                    TreeSet<HtmlParameter> cookiesTemp =
                            msgRedirect.getResponseHeader().getCookieParams();
                    for (Iterator<HtmlParameter> redirectSetsCookieIterator =
                                    cookiesTemp.iterator();
                            redirectSetsCookieIterator.hasNext(); ) {
                        HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
                        // loop through each of the cookies we know about in cookies, to see if it
                        // matches by name.
                        // if so, delete that cookie, and add the one that was just set to cookies.
                        // if not, add the one that was just set to cookies.
                        for (Iterator<HtmlParameter> knownCookiesIterator = cookies.iterator();
                                knownCookiesIterator.hasNext(); ) {
                            HtmlParameter knownCookie = knownCookiesIterator.next();
                            if (cookieJustSet.getName().equals(knownCookie.getName())) {
                                knownCookiesIterator.remove();
                                break; // out of the loop for known cookies, back to the next cookie
                                // set in the response
                            }
                        } // end of loop for cookies we already know about
                        // we can now safely add the cookie that was just set into cookies, knowing
                        // it does not clash with anything else in there.
                        cookies.add(cookieJustSet);
                    } // end of for loop for cookies just set in the redirect

                    msgCpy = msgRedirect; // store the last redirect message into the MsgCpy, as we
                    // will be using it's output in a moment..
                } // end of loop to follow redirects

                // now that the redirections have all been handled.. was the request finally a
                // success or not?  Successful or Failed Logins would normally both return an OK
                // HTTP status
                if (!HttpStatusCode.isSuccess(msgCpy.getResponseHeader().getStatusCode())) {
                    LOG.debug(
                            "The original URL [{}] returned a non-OK HTTP status {} (after {} of {} steps). Could be indicative of SQL Injection, or some other error. The URL is not stable enough to look at Username Enumeration",
                            getBaseMsg().getRequestHeader().getURI(),
                            msgCpy.getResponseHeader().getStatusCode(),
                            i,
                            numberOfRequests);
                    return; // we have not even got as far as looking at the parameters, so just
                    // abort straight out of the method
                }

                LOG.debug("Done following redirects!");

                // append the response to the responses so far for this particular instance
                // this will give us a complete picture of the full set of actual traffic associated
                // with following redirects for the request
                responseA.append(msgCpy.getResponseHeader().getHeadersAsString());
                responseA.append(msgCpy.getResponseBody().toString());

                // 2) Compute the longest common subsequence (LCS) of A[] into LCS_A
                // Note: in the Freiling and Schinzel method, this is calculated recursively. We
                // calculate it iteratively, but using an equivalent method

                // first time in, the LCS is simple: it's the first HTML result.. no diffing
                // required
                if (i == 0) longestCommonSubstringA = responseA.toString();
                // else get the LCS of the existing string, and the current result
                else
                    longestCommonSubstringA =
                            this.longestCommonSubsequence(
                                    longestCommonSubstringA, responseA.toString());

                // optimisation step: if the LCS of A is 0 characters long already, then the URL
                // output is not stable, and we can abort now, and save some time
                if (longestCommonSubstringA.length() == 0) {
                    // this might occur if the output returned for the URL changed mid-way. Perhaps
                    // a CAPTCHA has fired, or a WAF has kicked in.  Let's abort now so.
                    LOG.debug(
                            "The original URL [{}] does not produce stable output (at {} of {} steps).  There is no static element in the output that can be used as a basis of comparison for the result of requesting URLs with the parameter values modified. Perhaps a CAPTCHA or WAF has kicked in!!",
                            getBaseMsg().getRequestHeader().getURI(),
                            i + 1,
                            numberOfRequests);
                    return; // we have not even got as far as looking at the parameters, so just
                    // abort straight out of the method
                }
            }
            // get rid of any remnants of cookie setting and Date headers in the responses, as these
            // cause false positives, and can be safely ignored
            // replace the content length with a non-variable placeholder
            // replace url parameters with a non-variable placeholder to eliminate tokens in URLs in
            // the output
            longestCommonSubstringA =
                    longestCommonSubstringA.replaceAll("Set-Cookie:[^\\r\\n]+[\\r\\n]{1,2}", "");
            longestCommonSubstringA =
                    longestCommonSubstringA.replaceAll("Date:[^\\r\\n]+[\\r\\n]{1,2}", "");
            longestCommonSubstringA =
                    longestCommonSubstringA.replaceAll(
                            "Content-Length:[^\\r\\n]+[\\r\\n]{1,2}", "Content-Length: XXXX\n");
            longestCommonSubstringA =
                    longestCommonSubstringA.replaceAll(
                            "(?<=(&amp;|\\?)[^\\?\"=&;]+=)[^\\?\"=&;]+(?=(&amp;|\"))", "YYYY");

            LOG.debug("The LCS of A is [{}]", longestCommonSubstringA);

            // 3) for each parameter in the original URL (ie, for URL params, form params, and
            // cookie params)
            for (Iterator<HtmlParameter> iter = htmlParams.iterator(); iter.hasNext(); ) {

                HttpMessage msgModifiedParam = getNewMsg();
                HtmlParameter currentHtmlParameter = iter.next();

                LOG.debug(
                        "Handling [{}] parameter [{}], with value [{}]",
                        currentHtmlParameter.getType(),
                        currentHtmlParameter.getName(),
                        currentHtmlParameter.getValue());

                // 4) Change the current parameter value (which we assume is the username parameter)
                // to an invalid username (randomly), and request the URL n times. Store the results
                // in B[].

                // get a random user name the same length as the original!
                String invalidUsername =
                        RandomStringUtils.randomAlphabetic(currentHtmlParameter.getValue().length())
                                .toLowerCase(Locale.ROOT);

                LOG.debug("The invalid username chosen was [{}]", invalidUsername);

                TreeSet<HtmlParameter> requestParams = null;
                if (currentHtmlParameter.getType().equals(HtmlParameter.Type.cookie)) {
                    requestParams = msgModifiedParam.getRequestHeader().getCookieParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setCookieParams(requestParams);
                } else if (currentHtmlParameter.getType().equals(HtmlParameter.Type.url)) {
                    requestParams = msgModifiedParam.getUrlParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setGetParams(requestParams);
                } else if (currentHtmlParameter.getType().equals(HtmlParameter.Type.form)) {
                    requestParams = msgModifiedParam.getFormParams();
                    requestParams.remove(currentHtmlParameter);
                    requestParams.add(
                            new HtmlParameter(
                                    currentHtmlParameter.getType(),
                                    currentHtmlParameter.getName(),
                                    invalidUsername));
                    msgModifiedParam.setFormParams(requestParams);
                }

                LOG.debug(
                        "About to loop for {} iterations with an incorrect user of the same length",
                        numberOfRequests);

                boolean continueForParameter = true;
                for (int i = 0; i < numberOfRequests && continueForParameter; i++) {

                    responseB = new StringBuilder(250);

                    HttpMessage msgCpy = msgModifiedParam;

                    sendAndReceive(msgCpy, false, false);

                    TreeSet<HtmlParameter> cookies = msgCpy.getResponseHeader().getCookieParams();

                    int redirectCount = 0;
                    while (HttpStatusCode.isRedirection(
                            msgCpy.getResponseHeader().getStatusCode())) {
                        redirectCount++;

                        LOG.debug(
                                "Following redirect {} for message {} of {} iterations of the modified query.",
                                redirectCount,
                                i,
                                numberOfRequests);

                        // append the response to the responses so far for this particular instance
                        // this will give us a complete picture of the full set of actual traffic
                        // associated with following redirects for the request
                        responseB.append(msgCpy.getResponseHeader().getHeadersAsString());
                        responseB.append(msgCpy.getResponseBody().toString());

                        // and manually follow the redirect
                        // create a new message from scratch
                        HttpMessage msgRedirect = new HttpMessage();

                        // create a new URI from the absolute location returned, and interpret it as
                        // escaped
                        // note that the standard says that the Location returned should be
                        // absolute, but it ain't always so...
                        URI newLocation =
                                new URI(
                                        msgCpy.getResponseHeader().getHeader(HttpHeader.LOCATION),
                                        true);
                        try {
                            msgRedirect.getRequestHeader().setURI(newLocation);
                        } catch (Exception e) {
                            // the Location field contents may not be standards compliant. Lets
                            // generate a uri to use as a workaround where a relative path was
                            // given instead of an absolute one
                            URI newLocationWorkaround =
                                    new URI(
                                            msgCpy.getRequestHeader().getURI(),
                                            msgCpy.getResponseHeader()
                                                    .getHeader(HttpHeader.LOCATION),
                                            true);
                            // try again, except this time, if it fails, don't try to handle it
                            LOG.debug(
                                    "The Location [{}] specified in a redirect was not valid (not absolute?). Trying absolute workaround url [{}]",
                                    newLocation,
                                    newLocationWorkaround);
                            msgRedirect.getRequestHeader().setURI(newLocationWorkaround);
                        }
                        msgRedirect.getRequestHeader().setMethod(HttpRequestHeader.GET);
                        msgRedirect
                                .getRequestHeader()
                                .setContentLength(
                                        0); // since we send a GET, the body will be 0 long
                        if (!cookies.isEmpty()) {
                            // if a previous request sent back a cookie that has not since been
                            // invalidated, we need to set that cookie when following redirects, as
                            // a browser would
                            msgRedirect.getRequestHeader().setCookieParams(cookies);
                        }

                        sendAndReceive(
                                msgRedirect, false, false); // do NOT redirect.. handle it here

                        // handle scenario where a cookie is unset in a subsequent iteration, or
                        // where the same cookie name is later re-assigned a different value
                        // ie, in these cases, do not simply (and dumbly) accumulate cookie
                        // detritus.
                        // first get all cookies set in the response
                        TreeSet<HtmlParameter> cookiesTemp =
                                msgRedirect.getResponseHeader().getCookieParams();
                        for (Iterator<HtmlParameter> redirectSetsCookieIterator =
                                        cookiesTemp.iterator();
                                redirectSetsCookieIterator.hasNext(); ) {
                            HtmlParameter cookieJustSet = redirectSetsCookieIterator.next();
                            // loop through each of the cookies we know about in cookies, to see if
                            // it matches by name.
                            // if so, delete that cookie, and add the one that was just set to
                            // cookies.
                            // if not, add the one that was just set to cookies.
                            for (Iterator<HtmlParameter> knownCookiesIterator = cookies.iterator();
                                    knownCookiesIterator.hasNext(); ) {
                                HtmlParameter knownCookie = knownCookiesIterator.next();
                                if (cookieJustSet.getName().equals(knownCookie.getName())) {
                                    knownCookiesIterator.remove();
                                    break; // out of the loop for known cookies, back to the next
                                    // cookie set in the response
                                }
                            } // end of loop for cookies we already know about
                            // we can now safely add the cookie that was just set into cookies,
                            // knowing it does not clash with anything else in there.
                            cookies.add(cookieJustSet);
                        } // end of for loop for cookies just set in the redirect

                        msgCpy = msgRedirect; // store the last redirect message into the MsgCpy, as
                        // we will be using it's output in a moment..
                    } // end of loop to follow redirects

                    // now that the redirections have all been handled.. was the request finally a
                    // success or not?  Successful or Failed Logins would normally both return an OK
                    // HTTP status
                    if (!HttpStatusCode.isSuccess(msgCpy.getResponseHeader().getStatusCode())) {
                        LOG.debug(
                                "The modified URL [{}] returned a non-OK HTTP status {} (after {} of {} steps for [{}] parameter {}). Could be indicative of SQL Injection, or some other error. The URL is not stable enough to look at Username Enumeration",
                                msgModifiedParam.getRequestHeader().getURI(),
                                msgCpy.getResponseHeader().getStatusCode(),
                                i + 1,
                                numberOfRequests,
                                currentHtmlParameter.getType(),
                                currentHtmlParameter.getName());
                        continueForParameter = false;
                        continue; // skip directly to the next parameter
                    }

                    LOG.debug("Done following redirects!");

                    // append the response to the responses so far for this particular instance
                    // this will give us a complete picture of the full set of actual traffic
                    // associated with following redirects for the request
                    responseB.append(msgCpy.getResponseHeader().getHeadersAsString());
                    responseB.append(msgCpy.getResponseBody().toString());

                    // 5) Compute the longest common subsequence (LCS) of B[] into LCS_B
                    // Note: in the Freiling and Schinzel method, this is calculated recursively. We
                    // calculate it iteratively, but using an equivalent method

                    // first time in, the LCS is simple: it's the first HTML result.. no diffing
                    // required
                    if (i == 0) longestCommonSubstringB = responseB.toString();
                    // else get the LCS of the existing string, and the current result
                    else
                        longestCommonSubstringB =
                                this.longestCommonSubsequence(
                                        longestCommonSubstringB, responseB.toString());

                    // optimisation step: if the LCS of B is 0 characters long already, then the URL
                    // output is not stable, and we can abort now, and save some time
                    if (longestCommonSubstringB.length() == 0) {
                        // this might occur if the output returned for the URL changed mid-way.
                        // Perhaps a CAPTCHA has fired, or a WAF has kicked in.  Let's abort now so.
                        LOG.debug(
                                "The modified URL [{}] (for [{}] parameter {}) does not produce stable output (after {} of {} steps). There is no static element in the output that can be used as a basis of comparison with the static output of the original questy. Perhaps a CAPTCHA or WAF has kicked in!!",
                                msgModifiedParam.getRequestHeader().getURI(),
                                currentHtmlParameter.getType(),
                                currentHtmlParameter.getName(),
                                i + 1,
                                numberOfRequests);
                        continueForParameter = false;
                        continue; // skip directly to the next parameter.
                        // Note: if a CAPTCHA or WAF really has fired, the results of subsequent
                        // iterations will likely not be accurate..
                    }
                }

                // if we didn't hit something with one of the iterations for the parameter (ie, if
                // the output when changing the parm is stable),
                // check if the parameter might be vulnerable by comparins its LCS with the original
                // LCS for a valid login
                if (longestCommonSubstringB != null && continueForParameter) {
                    // get rid of any remnants of cookie setting and Date headers in the responses,
                    // as these cause false positives, and can be safely ignored
                    // replace the content length with a non-variable placeholder
                    // replace url parameters with a non-variable placeholder to eliminate tokens in
                    // URLs in the output
                    longestCommonSubstringB =
                            longestCommonSubstringB.replaceAll(
                                    "Set-Cookie:[^\\r\\n]+[\\r\\n]{1,2}", "");
                    longestCommonSubstringB =
                            longestCommonSubstringB.replaceAll("Date:[^\\r\\n]+[\\r\\n]{1,2}", "");
                    longestCommonSubstringB =
                            longestCommonSubstringB.replaceAll(
                                    "Content-Length:[^\\r\\n]+[\\r\\n]{1,2}",
                                    "Content-Length: XXXX\n");
                    longestCommonSubstringB =
                            longestCommonSubstringB.replaceAll(
                                    "(?<=(&amp;|\\?)[^\\?\"=&;]+=)[^\\?\"=&;]+(?=(&amp;|\"))",
                                    "YYYY");

                    LOG.debug("The LCS of B is [{}]", longestCommonSubstringB);

                    // 6) If LCS_A <> LCS_B, then there is a Username Enumeration issue on the
                    // current parameter
                    if (!longestCommonSubstringA.equals(longestCommonSubstringB)) {
                        // calculate line level diffs of the 2 Longest Common Substrings to aid the
                        // user in deciding if the match is a false positive
                        // get the diff as a series of patches
                        Patch<String> diffpatch =
                                DiffUtils.diff(
                                        new LinkedList<>(
                                                Arrays.asList(
                                                        longestCommonSubstringA.split("\\n"))),
                                        new LinkedList<>(
                                                Arrays.asList(
                                                        longestCommonSubstringB.split("\\n"))));

                        int numberofDifferences = diffpatch.getDeltas().size();

                        StringBuilder tempDiff = new StringBuilder(250);
                        for (Delta<String> delta : diffpatch.getDeltas()) {
                            String changeType = null;
                            if (delta.getType() == Delta.TYPE.CHANGE) changeType = "Changed Text";
                            else if (delta.getType() == Delta.TYPE.DELETE)
                                changeType = "Deleted Text";
                            else if (delta.getType() == Delta.TYPE.INSERT)
                                changeType = "Inserted text";
                            else changeType = "Unknown change type [" + delta.getType() + "]";

                            tempDiff.append("\n(" + changeType + ")\n"); // blank line before
                            tempDiff.append(
                                    "Output for Valid Username  : "
                                            + delta.getOriginal()
                                            + "\n"); // no blank lines
                            tempDiff.append(
                                    "\nOutput for Invalid Username: "
                                            + delta.getRevised()
                                            + "\n"); // blank line before
                        }
                        String diffAB = tempDiff.toString();
                        String extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.usernameenumeration.alert.extrainfo",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName(),
                                        currentHtmlParameter.getValue(), // original value
                                        invalidUsername, // new value
                                        diffAB, // the differences between the two sets of output
                                        numberofDifferences);
                        String attack =
                                Constant.messages.getString(
                                        "ascanbeta.usernameenumeration.alert.attack",
                                        currentHtmlParameter.getType(),
                                        currentHtmlParameter.getName());
                        String vulnname =
                                Constant.messages.getString("ascanbeta.usernameenumeration.name");
                        String vulndesc =
                                Constant.messages.getString("ascanbeta.usernameenumeration.desc");
                        String vulnsoln =
                                Constant.messages.getString("ascanbeta.usernameenumeration.soln");

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_LOW)
                                .setName(vulnname)
                                .setDescription(vulndesc)
                                .setParam(currentHtmlParameter.getName())
                                .setAttack(attack)
                                .setOtherInfo(extraInfo)
                                .setSolution(vulnsoln)
                                .setMessage(getBaseMsg())
                                .raise();

                    } else {
                        LOG.debug(
                                "[{}] parameter [{}] looks ok (Invalid Usernames cannot be distinguished from Valid usernames)",
                                currentHtmlParameter.getType(),
                                currentHtmlParameter.getName());
                    }
                }
            } // end of the for loop around the parameter list

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            LOG.error("An error occurred checking a url for Username Enumeration issues", e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    /**
     * gets the Longest Common Subsequence of two strings, using Dynamic programming techniques, and
     * minimal memory
     *
     * @param a the first String
     * @param b the second String
     * @return the Longest Common Subsequence of a and b
     */
    public String longestCommonSubsequence(String a, String b) {
        HirshbergMatcher hirschberg = new HirshbergMatcher();
        return hirschberg.getLCS(a, b);
    }

    private boolean shouldContinue(List<Context> contextList) {
        boolean hasAuth = false;
        for (Context context : contextList) {
            if (context.getAuthenticationMethod() instanceof FormBasedAuthenticationMethod) {
                hasAuth = true;
                break;
            }
        }
        return hasAuth;
    }

    @Override
    public int getCweId() {
        return 200; // CWE-200: Information Exposure
    }

    @Override
    public int getWascId() {
        return 13; // Info leakage
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
