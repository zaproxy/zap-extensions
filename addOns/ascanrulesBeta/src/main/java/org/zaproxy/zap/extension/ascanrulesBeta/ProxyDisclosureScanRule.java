/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

/**
 * Detect and fingerprint forward proxies and reverse proxies configured between the Zap instance
 * and the origin web server, and fingerprint the origin web server.
 *
 * @author 70pointer
 */
public class ProxyDisclosureScanRule extends AbstractAppPlugin {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.proxydisclosure.";

    public static final List<String> MAX_FORWARD_METHODS =
            new LinkedList<String>(
                    Arrays.asList(
                            new String[] {
                                HttpRequestHeader.TRACE, HttpRequestHeader.OPTIONS,
                            }));

    public static final Pattern NOT_SUPPORTED_APACHE_PATTERN =
            Pattern.compile(
                    "^<address>(.+)\\s+Server[^<]*</address>$",
                    Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
    public static final Pattern MAX_FORWARDS_RESPONSE_PATTERN =
            Pattern.compile(
                    "^Max-Forwards:\\s*([0-9]+)\\s*$",
                    Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    /**
     * a map of patterns indicating any cookies set by a proxy. Use a capture group for the cookie
     * name.
     */
    public static final Map<Pattern, String> PROXY_COOKIES = new LinkedHashMap<Pattern, String>();

    static {
        // Citrix NetScaler
        PROXY_COOKIES.put(
                Pattern.compile(
                        "Set-Cookie: (NSC_[a-z0-9]+)=",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "Citrix NetScaler");
    }

    /**
     * a map of any request headers set by a proxy. Use a capture group for the header name, and
     * another for the value.
     */
    public static final Map<Pattern, String> PROXY_REQUEST_HEADERS =
            new LinkedHashMap<Pattern, String>();

    static {
        // product-specific headers go first..

        // generic headers set by proxies go after..
        PROXY_REQUEST_HEADERS.put(
                Pattern.compile(
                        "^(X-Forwarded-For):\\s*([0-9.]+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_REQUEST_HEADERS.put(
                Pattern.compile(
                        "^(X-Forwarded-Port):\\s*([0-9]+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_REQUEST_HEADERS.put(
                Pattern.compile(
                        "^(X-Forwarded-Proto):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_REQUEST_HEADERS.put(
                Pattern.compile(
                        "^(Via):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        // Don't put Cache-Control in here, since we send TRACE requests with the "Cache-Control"
        // header in step 1.
        // If the TRACE succeeds, the Cache-Control directive we send is echoed back in the
        // response, and it looks like we're after
        // detecting a proxy. D'oh!
        // PROXY_REQUEST_HEADERS.put(Pattern.compile("^(Cache-Control):\\s*(.+)\\s*$",
        // Pattern.CASE_INSENSITIVE |  Pattern.MULTILINE | Pattern.DOTALL), "");
    }

    /**
     * a map of any response headers set by a proxy. Use a capture group for the header name, and
     * another for the value.
     */
    public static final Map<Pattern, String> PROXY_RESPONSE_HEADERS =
            new LinkedHashMap<Pattern, String>();

    static {
        PROXY_RESPONSE_HEADERS.put(
                Pattern.compile(
                        "^(X-RBT-Optimized-By):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "Riverbed Steelhead");

        PROXY_RESPONSE_HEADERS.put(
                Pattern.compile(
                        "^(X-Cache):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_RESPONSE_HEADERS.put(
                Pattern.compile(
                        "^(X-Cache-Lookup):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_RESPONSE_HEADERS.put(
                Pattern.compile(
                        "^(Via):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
        PROXY_RESPONSE_HEADERS.put(
                Pattern.compile(
                        "^(Cache-Control):\\s*(.+)\\s*$",
                        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
                "");
    }

    /** the number of Max-Forwards to apply. Set depending on the Attack strength. */
    private int MAX_FORWARDS_MAXIMUM = 0;

    /** for logging. */
    private static Logger log = Logger.getLogger(ProxyDisclosureScanRule.class);

    @Override
    public int getId() {
        return 40025;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return null;
        // needs a parameter!
        // return Constant.messages.getString(MESSAGE_PREFIX+"desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void init() {

        // set up what we are allowed to do, depending on the attack strength that was set.
        if (this.getAttackStrength() == AttackStrength.LOW) {
            MAX_FORWARDS_MAXIMUM = 2;
        } else if (this.getAttackStrength() == AttackStrength.MEDIUM) {
            MAX_FORWARDS_MAXIMUM = 3;
        } else if (this.getAttackStrength() == AttackStrength.HIGH) {
            MAX_FORWARDS_MAXIMUM = 4;
        } else if (this.getAttackStrength() == AttackStrength.INSANE) {
            MAX_FORWARDS_MAXIMUM = 5;
        }
    }

    /**
     * scans for Proxy Disclosure issues, using the TRACE and OPTIONS method with 'Max-Forwards',
     * and the TRACK method. The code attempts to enumerate and identify all proxies identified
     * between the Zap instance and the origin web server.
     */
    @Override
    public void scan() {
        try {
            // where's what we're going to do (roughly):
            // 1: If TRACE is enabled on the origin web server, we're going to use it, and the
            // "Max-Forwards" header to verify
            //	 if *no* proxy exists between Zap and the origin web server.
            // 2: If we can't do that, because TRACE is not supported, or because there appears to
            // be a proxy between Zap
            //   and the origin web server, we use the "Max-Forwards" compatible methods (TRACE and
            // OPTIONS) to
            //	 iterate through each of the proxies between Zap and the origin web server.
            //	 We will attempt to fingerprint each proxy / web server along the way, using various
            // techniques.
            // 3: At this point, depending on the proxies and their configurations, there is a
            // possibility that we have not
            //	 identified *all* of the nodes (proxies / web servers) that the request/response
            // traverses.  We will use
            //	 other HTTP methods, such as "TRACK" to obtain an error-type response. In all of the
            // cases we have tested so far,
            //   such an error response comes from the origin web server, rather than an
            // intermediate proxy.  We then fingerprint
            //	 the origin web server.  If the origin web server's signature is not the same as the
            // final node that we have
            //	 already identified, we consider the origin web server to be an additional node in
            // the path.
            // 4: Report the results.

            // Step 1: Using TRACE, identify if *no* proxies are used between the Zap instance and
            // the origin web server
            // int maxForwardsMaximum = 7;  //Anonymous only use 7 proxies, so that's good enough
            // for us too.. :)
            int step1numberOfProxies = 0;
            // this variable is to track proxies that set cookies, but are otherwise complete
            // invisible, and do not
            // respond per spec (RFC2616, RFC2965) to OPTIONS/TRACE with Max-Forwards.
            // They do not set headers that can be identified.
            // They are also inherently un-ordered, because we do not, and cannot be sure at what
            // point they fit into the topology
            // that we can otherwise document using OPTIONS/TRACE + Max-Forwards.
            Set<String> silentProxySet = new HashSet<String>();
            boolean endToEndTraceEnabled = false;
            boolean proxyTraceEnabled = false;

            URI traceURI = getBaseMsg().getRequestHeader().getURI();
            HttpRequestHeader traceRequestHeader = new HttpRequestHeader();
            traceRequestHeader.setMethod(HttpRequestHeader.TRACE);
            // go to the URL requested, in case the proxy is configured on a per-URL basis..
            // traceRequestHeader.setURI(new URI(traceURI.getScheme() + "://" +
            // traceURI.getAuthority()+ "/",true));
            traceRequestHeader.setURI(traceURI);
            traceRequestHeader.setVersion(HttpRequestHeader.HTTP11); // or 1.1?
            traceRequestHeader.setSecure(traceRequestHeader.isSecure());
            traceRequestHeader.setHeader("Max-Forwards", String.valueOf(MAX_FORWARDS_MAXIMUM));
            traceRequestHeader.setHeader(
                    "Cache-Control",
                    "no-cache"); // we do not want cached content. we want content from the origin
            // server
            traceRequestHeader.setHeader("Pragma", "no-cache"); // similarly, for HTTP/1.0

            HttpMessage tracemsg = getNewMsg();
            tracemsg.setRequestHeader(traceRequestHeader);
            // create a random cookie, and set it up, so we can detect if the TRACE is enabled (in
            // which case, it should echo it back in the response)
            String randomcookiename =
                    RandomStringUtils.random(
                            15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            String randomcookievalue =
                    RandomStringUtils.random(
                            40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            TreeSet<HtmlParameter> cookies = tracemsg.getCookieParams();
            cookies.add(
                    new HtmlParameter(
                            HtmlParameter.Type.cookie, randomcookiename, randomcookievalue));
            tracemsg.setCookieParams(cookies);

            sendAndReceive(tracemsg, false); // do not follow redirects.
            // is TRACE enabled?
            String traceResponseBody = tracemsg.getResponseBody().toString();
            if (traceResponseBody.contains(randomcookievalue)) {
                // TRACE is enabled. Look at the Max-Forwards in the response, to see if it was
                // decremented
                // if it was decremented, there is definitely a proxy..
                // if not, it *suggests* there is no proxy (or any proxies present are not compliant
                // --> all bets are off)
                boolean proxyActuallyFound = false;
                // found a TRACE from Zap all the way through to the Origin server.. not good!!
                endToEndTraceEnabled =
                        true; // this will raise the risk from Medium to High if a Proxy Disclosure
                // was found!
                // TODO: raise a "TRACE" type alert (if no proxy disclosure is found, but TRACE
                // enabled?)

                Matcher matcher = MAX_FORWARDS_RESPONSE_PATTERN.matcher(traceResponseBody);
                if (matcher.find()) {
                    String maxForwardsResponseValue = matcher.group(1);
                    if (log.isDebugEnabled())
                        log.debug(
                                "TRACE with \"Max-Forwards: "
                                        + MAX_FORWARDS_MAXIMUM
                                        + "\" causes response body Max-Forwards value '"
                                        + maxForwardsResponseValue
                                        + "'");
                    if (maxForwardsResponseValue.equals(String.valueOf(MAX_FORWARDS_MAXIMUM))) {
                        // (probably) no proxy!
                        if (log.isDebugEnabled())
                            log.debug(
                                    "TRACE with \"Max-Forwards: "
                                            + MAX_FORWARDS_MAXIMUM
                                            + "\" indicates that there is *NO* proxy in place. Note: the TRACE method is supported.. that's an issue in itself! :)");

                        // To be absolutely certain, check that the cookie info in the response
                        // header,
                        // and proxy request headers in the response body (via TRACE) do not leak
                        // the presence of a proxy
                        // This would indicate a non-RFC2606 compliant proxy, since these are
                        // supposed to decrement the Max-Forwards.
                        // it does happen in the wild..
                        String traceResponseHeader = tracemsg.getResponseHeader().toString();

                        // look for cookies set by the proxy, which will be in the response header
                        Iterator<Pattern> cookiePatternIterator = PROXY_COOKIES.keySet().iterator();
                        while (cookiePatternIterator.hasNext() && !proxyActuallyFound) {
                            Pattern cookiePattern = cookiePatternIterator.next();
                            String proxyServer = PROXY_COOKIES.get(cookiePattern);
                            Matcher cookieMatcher = cookiePattern.matcher(traceResponseHeader);
                            if (cookieMatcher.find()) {
                                String cookieDetails = cookieMatcher.group(1);
                                if (log.isDebugEnabled()) {
                                    proxyActuallyFound = true;
                                    if (!proxyServer.equals("")
                                            && !silentProxySet.contains(proxyServer))
                                        silentProxySet.add(proxyServer);
                                    if (log.isDebugEnabled())
                                        log.debug(
                                                "TRACE with \"Max-Forwards: "
                                                        + MAX_FORWARDS_MAXIMUM
                                                        + "\" indicates that there is *NO* proxy in place, but a known proxy cookie ("
                                                        + cookieDetails
                                                        + ", which indicates proxy server '"
                                                        + proxyServer
                                                        + "') in the response header contradicts this..");
                                }
                            }
                        }
                        // look for request headers set by the proxy, which will end up in the
                        // response body if the TRACE succeeded
                        Iterator<Pattern> requestHeaderPatternIterator =
                                PROXY_REQUEST_HEADERS.keySet().iterator();
                        while (requestHeaderPatternIterator.hasNext() && !proxyActuallyFound) {
                            Pattern proxyHeaderPattern = requestHeaderPatternIterator.next();
                            String proxyServer = PROXY_REQUEST_HEADERS.get(proxyHeaderPattern);
                            Matcher proxyHeaderMatcher =
                                    proxyHeaderPattern.matcher(traceResponseBody);
                            if (proxyHeaderMatcher.find()) {
                                String proxyHeaderName = proxyHeaderMatcher.group(1);
                                if (log.isDebugEnabled()) {
                                    proxyActuallyFound = true;
                                    if (log.isDebugEnabled())
                                        log.debug(
                                                "TRACE with \"Max-Forwards: "
                                                        + MAX_FORWARDS_MAXIMUM
                                                        + "\" indicates that there is *NO* proxy in place, but a known proxy request header ("
                                                        + proxyHeaderName
                                                        + ", which indicates proxy server '"
                                                        + proxyServer
                                                        + "') in the response body contradicts this..");
                                }
                            }
                        }

                    } else {
                        // Trace indicates there is a proxy in place.. (or multiple proxies)
                        // Note: this number cannot really be trusted :( we don't use it, other than
                        // for informational purposes
                        step1numberOfProxies =
                                MAX_FORWARDS_MAXIMUM - Integer.parseInt(maxForwardsResponseValue);
                        if (log.isDebugEnabled())
                            log.debug(
                                    "TRACE with \"Max-Forwards: "
                                            + MAX_FORWARDS_MAXIMUM
                                            + "\" indicates that there *IS* at least one proxy in place (Likely number: "
                                            + step1numberOfProxies
                                            + "). Note: the TRACE method is also supported!");
                        proxyActuallyFound = true;
                    }
                } else {
                    // The Max-Forwards does not appear in the response body, even though the cookie
                    // value appeared in the response body, using TRACE.. Why?
                    if (log.isDebugEnabled())
                        log.debug(
                                "TRACE support is indicated via an echoed cookie, but the Max-Forwards value from the request is not echoed in the response. Why? Load balancer? WAF?");
                    proxyActuallyFound = true;
                }
                // no conflicting evidence (ie, no proxy indicated) ==> return
                if (!proxyActuallyFound) return;
            } else {
                // TRACE is NOT enabled, so we can't use this technique to tell if there is *no*
                // proxy between Zap and the origin server
                if (log.isDebugEnabled())
                    log.debug(
                            "TRACE is not supported, so we cannot quickly check for *no* proxies. Falling back to the hard way");
            }

            // bale out if we were asked nicely. it's nice to be nice.
            if (isStop()) {
                if (log.isDebugEnabled())
                    log.debug("Stopping the scan due to a user request (after step 1)");
                return;
            }

            // Step 2: Use Max-Forwards with OPTIONS and TRACE to iterate through each of the
            // proxies
            HttpRequestHeader baseRequestHeader = getBaseMsg().getRequestHeader();
            URI baseRequestURI = baseRequestHeader.getURI();
            int step2numberOfNodes = 0;
            String[] nodeServers =
                    new String[MAX_FORWARDS_MAXIMUM + 2]; // up to n proxies, and an origin server.

            // for each of the methods
            for (String httpMethod : MAX_FORWARD_METHODS) {
                // for each method, increment the Max-Forwards, and look closely at the response
                // TODO: loop from 0 to numberOfProxies -1????
                int step2numberOfNodesForMethod = 0;
                String[] nodeServersForMethod = new String[MAX_FORWARDS_MAXIMUM + 2];
                String previousServerDetails =
                        RandomStringUtils.random(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
                int previousResponseStatusCode = 0;
                int responseStatusCode = 0;
                boolean httpHandled =
                        false; // a flag to handle an extra HTTP request for this method, if the URL
                // is HTTPS

                // if the TRACE worked in step 1, and we know how many proxies there are, do that
                // number + 1, else just do the maximum defined on the attack strength
                for (int maxForwards = 0;
                        maxForwards
                                < (step1numberOfProxies > 0
                                        ? step1numberOfProxies + 1
                                        : MAX_FORWARDS_MAXIMUM);
                        maxForwards++) {

                    HttpMessage testMsg =
                            getNewMsg(); // get a new message, with the request attributes cloned
                    // from the base message
                    HttpRequestHeader origRequestHeader = testMsg.getRequestHeader();

                    if (log.isDebugEnabled())
                        log.debug(
                                "Trying method "
                                        + httpMethod
                                        + " with MAX-FORWARDS: "
                                        + Integer.toString(maxForwards));

                    // if we're on the right iteration (Max-Forwards=0, i.e. first proxy, and a
                    // HTTPS request,
                    // then prepare to try an additional HTTP request..
                    boolean tryHttp =
                            (!httpHandled && maxForwards == 0 && baseRequestHeader.isSecure());

                    HttpRequestHeader requestHeader = new HttpRequestHeader();
                    requestHeader.setMethod(httpMethod);
                    // requestHeader.setURI(new URI(origURI.getScheme() + "://" +
                    // origURI.getAuthority()+ "/",true));
                    requestHeader.setURI(baseRequestURI);
                    requestHeader.setVersion(
                            HttpRequestHeader
                                    .HTTP11); // OPTIONS and TRACE are supported under 1.0, but for
                    // multi-homing, we need to use 1.1
                    if (tryHttp) {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "Blind-spot testing, using a HTTP connection, to try detect an initial proxy, which we might not see via HTTPS");
                        requestHeader.setSecure(false);
                        requestHeader.setHeader("Max-Forwards", "0");
                    } else {
                        requestHeader.setSecure(origRequestHeader.isSecure());
                        requestHeader.setHeader("Max-Forwards", Integer.toString(maxForwards));
                    }
                    requestHeader.setHeader(
                            "Cache-Control",
                            "no-cache"); // we do not want cached content. we want content from the
                    // origin server
                    requestHeader.setHeader("Pragma", "no-cache"); // similarly, for HTTP/1.0

                    HttpMessage mfMethodMsg = getNewMsg();
                    mfMethodMsg.setRequestHeader(requestHeader);

                    // create a random cookie, and set it up, so we can detect if the TRACE is
                    // enabled (in which case, it should echo it back in the response)
                    String randomcookiename2 =
                            RandomStringUtils.random(
                                    15,
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
                    String randomcookievalue2 =
                            RandomStringUtils.random(
                                    40,
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
                    TreeSet<HtmlParameter> cookies2 = mfMethodMsg.getCookieParams();
                    cookies2.add(
                            new HtmlParameter(
                                    HtmlParameter.Type.cookie,
                                    randomcookiename2,
                                    randomcookievalue2));
                    mfMethodMsg.setCookieParams(cookies2);

                    try {
                        sendAndReceive(mfMethodMsg, false); // do not follow redirects.
                    } catch (Exception e) {
                        log.error(
                                "Failed to send a request in step 2 with method "
                                        + httpMethod
                                        + ", Max-Forwards: "
                                        + requestHeader.getHeader("Max-Forwards")
                                        + ": "
                                        + e.getMessage());
                        break; // to the next method
                    }

                    // if the response from the proxy/origin server echoes back the cookie (TRACE,
                    // or other method), that's serious, so we need to check.
                    String methodResponseBody = mfMethodMsg.getResponseBody().toString();
                    if (methodResponseBody.contains(randomcookievalue2)) {
                        proxyTraceEnabled =
                                true; // this will raise the risk from Medium to High if a Proxy
                        // Disclosure was found!
                        // TODO: raise a "TRACE" type alert (if no proxy disclosure is found, but
                        // TRACE enabled?)
                    }

                    // check if the Server response header differs
                    // the server header + powered by list is what we will record if a key attribute
                    // changes between requests.
                    HttpResponseHeader responseHeader = mfMethodMsg.getResponseHeader();
                    String serverHeader = responseHeader.getHeader("Server");
                    if (serverHeader == null) serverHeader = "";

                    String poweredBy;
                    List<String> poweredByList = responseHeader.getHeaderValues("X-Powered-By");
                    if (!poweredByList.isEmpty())
                        poweredBy = poweredByList.toString(); // uses format: "[a,b,c]"
                    else poweredBy = "";
                    String serverDetails =
                            serverHeader
                                    + (poweredBy.equals("") || poweredBy.equals("[]")
                                            ? ""
                                            : poweredBy);
                    responseStatusCode = responseHeader.getStatusCode();

                    if (!serverDetails.equals(previousServerDetails)) {
                        // it's a new node that we don't appear to have previously seen (for this
                        // HTTP method).
                        nodeServersForMethod[step2numberOfNodesForMethod] = serverDetails;
                        step2numberOfNodesForMethod++;
                        if (log.isDebugEnabled())
                            log.debug(
                                    "Identified a new node for method "
                                            + httpMethod
                                            + ", by server details: "
                                            + serverDetails
                                            + ". That makes "
                                            + step2numberOfNodesForMethod
                                            + " nodes so far");
                    } else {
                        // else check if the HTTP status code differs
                        if (responseStatusCode != previousResponseStatusCode) {
                            // if the status code is different, this likely indicates a different
                            // node
                            nodeServersForMethod[step2numberOfNodesForMethod] = serverDetails;
                            step2numberOfNodesForMethod++;
                            if (log.isDebugEnabled())
                                log.debug(
                                        "Identified a new node for method "
                                                + httpMethod
                                                + ", by response status : "
                                                + responseStatusCode
                                                + ". That makes "
                                                + step2numberOfNodesForMethod
                                                + " nodes so far");
                        }
                    }
                    previousServerDetails = serverDetails;
                    previousResponseStatusCode = responseStatusCode;

                    // if the base URL is HTTPS, and we just did an extra "blind spot" check for
                    // HTTP, go into the next iteration with the same
                    // "Max-Forwards" value that we just handled, but set the flag to false so that
                    // we don't attempt to do the HTTP "blind spot" request again.
                    if (tryHttp) {
                        maxForwards--;
                        httpHandled = true;
                    }

                    // bale out if we were asked nicely. it's nice to be nice.
                    if (isStop()) {
                        if (log.isDebugEnabled())
                            log.debug("Stopping the scan due to a user request");
                        return;
                    }
                }
                // if the number of nodes (proxies+origin web server) detected using this HTTP
                // method is greater than the number detected thus far, use the data
                // gained using this HTTP method..
                if (log.isDebugEnabled())
                    log.debug(
                            "The number of nodes detected using method "
                                    + httpMethod
                                    + " is "
                                    + step2numberOfNodesForMethod);
                if (step2numberOfNodesForMethod > step2numberOfNodes) {
                    step2numberOfNodes = step2numberOfNodesForMethod;
                    nodeServers = nodeServersForMethod;
                }
            }
            if (log.isDebugEnabled())
                log.debug(
                        "The maximum number of nodes detected using any Max-Forwards method  is "
                                + step2numberOfNodes);

            // Step 3: For the TRACK, use a random URL, to force an error, and to bypass any cached
            // file.
            URI trackURI = getBaseMsg().getRequestHeader().getURI();
            HttpRequestHeader trackRequestHeader = new HttpRequestHeader();
            trackRequestHeader.setMethod(
                    "TRACK"); // There is no suitable constant on HttpRequestHeader
            // go to a similar (but random) URL requested
            //	- in case a proxy is configured on a per-URL basis.. (this is the case on some of my
            // real world test servers)
            //	- to try to ensure we get an error message that we can fingerprint
            //	- to bypass caching (if it's a random filename, if won't have been seen before, and
            // won't be cached)
            //	  yes, I know TRACK requests should *not* be cached, but not all servers are
            // compliant.
            String randompiece =
                    RandomStringUtils.random(5, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
            trackRequestHeader.setURI(
                    new URI(
                            trackURI.getScheme()
                                    + "://"
                                    + trackURI.getAuthority()
                                    + getPath(trackURI)
                                    + randompiece,
                            true));

            trackRequestHeader.setVersion(HttpRequestHeader.HTTP11); //
            trackRequestHeader.setSecure(trackRequestHeader.isSecure());
            trackRequestHeader.setHeader("Max-Forwards", String.valueOf(MAX_FORWARDS_MAXIMUM));
            trackRequestHeader.setHeader(
                    "Cache-Control",
                    "no-cache"); // we do not want cached content. we want content from the origin
            // server
            trackRequestHeader.setHeader("Pragma", "no-cache"); // similarly, for HTTP/1.0

            HttpMessage trackmsg = getNewMsg();
            trackmsg.setRequestHeader(trackRequestHeader);

            sendAndReceive(trackmsg, false); // do not follow redirects.

            // TODO: fingerprint more origin web servers response to a TRACK request for a file that
            // does not exist.
            String trackResponseBody = trackmsg.getResponseBody().toString();
            Matcher unsupportedApacheMatcher =
                    NOT_SUPPORTED_APACHE_PATTERN.matcher(trackResponseBody);
            if (unsupportedApacheMatcher.find()) {
                String originServerName = unsupportedApacheMatcher.group(1);
                if (log.isDebugEnabled())
                    log.debug(
                            "Identified the origin node using TRACK, with server header: "
                                    + originServerName);
                // check if this is the same as the last node we've identified, and if so, discard
                // it. If not, add it to to the end (as the origin server).
                if (!nodeServers[step2numberOfNodes - 1].equals(originServerName)) {
                    // it's different to the last one seen.. add it.
                    if (log.isDebugEnabled())
                        log.debug(
                                "The origin node was not already recorded using the Max-Forwards method, so adding it in.");
                    nodeServers[step2numberOfNodes] = originServerName;
                    step2numberOfNodes++;
                }
            }

            // TODO: compare step2numberOfProxies and step1numberOfProxies?

            // log the nodes we have noted so far
            if (log.isDebugEnabled()) {
                for (int nodei = 0; nodei < step2numberOfNodes; nodei++) {
                    log.debug(
                            "Node "
                                    + nodei
                                    + " is "
                                    + (!nodeServers[nodei].equals("")
                                            ? nodeServers[nodei]
                                            : "Unknown"));
                }
                // log the "silent" proxies that we saw.
                for (String silentServer : silentProxySet) {
                    log.debug(
                            "Silent Proxy: "
                                    + (!silentServer.equals("") ? silentServer : "Unknown"));
                }
            }

            // Note: there will always be an origin web server, so check for >1, not <0 number of
            // nodes.
            if (step2numberOfNodes > 1 || silentProxySet.size() > 0) {
                // bingo with the list of nodes (proxies+origin web server) that we detected.
                String unknown = Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.unknown");
                String proxyServerHeader =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo.proxyserver.header");
                String webServerHeader =
                        Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.webserver.header");
                String silentProxyServerHeader =
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo.silentproxyserver.header");

                // get the proxy server information (ie, all but the last node)
                String proxyServerInfo = "";
                if (step2numberOfNodes > 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(proxyServerHeader);
                    sb.append("\n");
                    for (int nodei = 0; nodei < step2numberOfNodes - 1; nodei++) {
                        String proxyServerNode =
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.proxyserver",
                                        (!nodeServers[nodei].equals("")
                                                ? nodeServers[nodei]
                                                : unknown));
                        sb.append(proxyServerNode);
                        sb.append("\n");
                    }
                    proxyServerInfo = sb.toString();
                }
                // get the origin web server information (ie, the last node)
                String webServerInfo = "";
                if (step2numberOfNodes > 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(webServerHeader);
                    sb.append("\n");
                    String webServerNode =
                            Constant.messages.getString(
                                    MESSAGE_PREFIX + "extrainfo.webserver",
                                    (!nodeServers[step2numberOfNodes - 1].equals("")
                                            ? nodeServers[step2numberOfNodes - 1]
                                            : unknown));
                    sb.append(webServerNode);
                    sb.append("\n");
                    webServerInfo = sb.toString();
                }
                // get the silent proxy information
                String silentProxyServerInfo = "";
                if (silentProxySet.size() > 0) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(silentProxyServerHeader);
                    sb.append("\n");
                    for (String silentServer : silentProxySet) {
                        // log.debug("Silent Proxy:
                        // "+(!silentServer.equals("")?silentServer:"Unknown"));
                        String silentProxyServerNode =
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.silentproxyserver",
                                        (!silentServer.equals("") ? silentServer : unknown));
                        sb.append(silentProxyServerNode);
                        sb.append("\n");
                    }
                    silentProxyServerInfo = sb.toString();
                }
                String traceInfo = "";
                if (endToEndTraceEnabled || proxyTraceEnabled) {
                    traceInfo =
                            Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.traceenabled");
                }

                // all the info is collated nicely. raise the alert.
                String extraInfo = "";
                if (!proxyServerInfo.equals("")) {
                    extraInfo += proxyServerInfo;
                }
                if (!webServerInfo.equals("")) {
                    extraInfo += webServerInfo;
                }
                if (!silentProxyServerInfo.equals("")) {
                    extraInfo += silentProxyServerInfo;
                }
                if (!traceInfo.equals("")) {
                    extraInfo += traceInfo;
                }

                // raise the alert on the original message
                // there are multiple messages on which the issue could have been raised, but each
                // individual atatck message
                // tells only a small part of the story. Explain it in the "extra info" instead.
                newAlert()
                        .setRisk(
                                endToEndTraceEnabled || proxyTraceEnabled
                                        ? Alert.RISK_HIGH
                                        : getRisk())
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "desc",
                                        step2numberOfNodes - 1 + silentProxySet.size()))
                        .setAttack(getAttack())
                        .setOtherInfo(extraInfo)
                        .setMessage(getBaseMsg())
                        .raise();
            }

        } catch (Exception e) {
            // Do not try to internationalise this.. we need an error message in any event..
            // if it's in English, it's still better than not having it at all.
            log.error("An error occurred checking for proxy disclosure", e);
        }
    }

    private String getPath(URI uri) {
        String path = uri.getEscapedPath();
        if (path != null) {
            return path;
        }
        return "/";
    }

    private String getAttack() {
        return Constant.messages.getString(MESSAGE_PREFIX + "attack");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 200; // Information Exposure (primarily via TRACE / OPTIONS / TRACK)
    }

    @Override
    public int getWascId() {
        return 45; // Fingerprinting
    }
}
