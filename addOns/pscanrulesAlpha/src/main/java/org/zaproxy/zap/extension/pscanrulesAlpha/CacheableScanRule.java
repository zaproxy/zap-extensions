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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.util.DateParseException;
import org.apache.commons.httpclient.util.DateUtil;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Detect "storable" and "cacheable" reponses. "Storable" implies that the response can be stored in
 * some manner by the caching server, even if it is not served in response to any requests.
 * "Cacheable" responses are responses that are served by the caching server in response to some
 * request. Unlike "CacheControlScanner", this rule does not attempt to determine if the various
 * cache settings are "incorrectly" set (since that depends on the response contents, and on the
 * context), but instead, looks at the conditions defined in rfc7234 to determine if a given request
 * and response are storable by rfc7234 compliant cache servers, and subsequently retrievable from
 * the cache (ie, "cacheable"):
 *
 * <p>A cache MUST NOT store a response to any request, unless: o The request method is understood
 * by the cache and defined as being cacheable, and o the response status code is understood by the
 * cache, and o the "no-store" cache directive (see Section 5.2) does not appear in request or
 * response header fields, and o the "private" response directive (see Section 5.2.2.6) does not
 * appear in the response, if the cache is shared, and o the Authorization header field (see Section
 * 4.2 of [RFC7235]) does not appear in the request, if the cache is shared, unless the response
 * explicitly allows it (see Section 3.2), and o the response either: * contains an Expires header
 * field (see Section 5.3), or * contains a max-age response directive (see Section 5.2.2.8), or *
 * contains a s-maxage response directive (see Section 5.2.2.9) and the cache is shared, or *
 * contains a Cache Control Extension (see Section 5.2.3) that allows it to be cached, or * has a
 * status code that is defined as cacheable by default (see Section 4.2.2), or * contains a public
 * response directive (see Section 5.2.2.5). Note that any of the requirements listed above can be
 * overridden by a cache-control extension; see Section 5.2.3.
 *
 * <p>When presented with a request, a cache MUST NOT reuse a stored response, unless: o The
 * presented effective request URI (Section 5.5 of [RFC7230]) and that of the stored response match,
 * and o the request method associated with the stored response allows it to be used for the
 * presented request, and o selecting header fields nominated by the stored response (if any) match
 * those presented (see Section 4.1), and o the presented request does not contain the no-cache
 * pragma (Section 5.4), nor the no-cache cache directive (Section 5.2.1), unless the stored
 * response is successfully validated (Section 4.3), and o the stored response does not contain the
 * no-cache cache directive (Section 5.2.2.2), unless it is successfully validated (Section 4.3),
 * and o the stored response is either: * fresh (see Section 4.2), or * allowed to be served stale
 * (see Section 4.2.4), or * successfully validated (see Section 4.3). Note that any of the
 * requirements listed above can be overridden by a cache-control extension; see Section 5.2.3.
 *
 * @author 70pointer@gmail.com
 */
public class CacheableScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX_STORABILITY_CACHEABILITY =
            "pscanalpha.storabilitycacheability.";
    private static final String MESSAGE_PREFIX_NONSTORABLE = "pscanalpha.nonstorable.";
    private static final String MESSAGE_PREFIX_STORABLE_NONCACHEABLE =
            "pscanalpha.storablenoncacheable.";
    private static final String MESSAGE_PREFIX_STORABLE_CACHEABLE = "pscanalpha.storablecacheable.";
    private static final int PLUGIN_ID = 10049;

    private static final Logger logger = Logger.getLogger(CacheableScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this scan rule
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        // TODO: standardise the logic in the case of duplicate / conflicting headers.
        try {
            if (logger.isDebugEnabled())
                logger.debug(
                        "Checking URL "
                                + msg.getRequestHeader().getURI().getURI()
                                + " for storability");

            // storability: is the request method understood by the cache and defined as being
            // cacheable?
            String method = msg.getRequestHeader().getMethod();
            String methodUpper = method.toUpperCase();
            if (!(methodUpper.equals(HttpRequestHeader.GET)
                    || methodUpper.equals(HttpRequestHeader.HEAD)
                    || methodUpper.equals(HttpRequestHeader.POST))) {
                // non-cacheable method ==> non-storable
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " is not storable due to the use of the non-cacheable request method '"
                                    + method
                                    + "'");
                alertNonStorable(msg, id, method + " ");
                return;
            }

            // is the response status code "understood" by the cache?
            // this is somewhat implementation specific, so lets assume that a cache "understands"
            // all 1XX, 2XX, 3XX, 4XX, and 5XX response classes for now.
            // this logic will allow us to detect if the response is storable by "some" compliant
            // caching server
            int responseClass = msg.getResponseHeader().getStatusCode() / 100;
            if ((responseClass != 1)
                    && (responseClass != 2)
                    && (responseClass != 3)
                    && (responseClass != 4)
                    && (responseClass != 5)) {
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " is not storable due to the use of a HTTP response class ["
                                    + responseClass
                                    + "] that we do not 'understand' (we 'understand' 1XX, 2XX, 3XX, 4XX, and 5XX response classes)");
                alertNonStorable(msg, id, String.valueOf(msg.getResponseHeader().getStatusCode()));
                return;
            }

            // does the "no-store" cache directive appear in request or response header fields?
            // 1: check the Pragma request header (for HTTP 1.0 caches)
            // 2: check the Pragma response header (for HTTP 1.0 caches)
            // 3: check the Cache-Control request header (for HTTP 1.1 caches)
            // 4: check the Cache-Control response header (for HTTP 1.1 caches)
            List<String> headers = new ArrayList<>();
            headers.addAll(msg.getRequestHeader().getHeaderValues(HttpHeader.PRAGMA));
            headers.addAll(msg.getResponseHeader().getHeaderValues(HttpHeader.PRAGMA));
            headers.addAll(msg.getRequestHeader().getHeaderValues(HttpHeader.CACHE_CONTROL));
            headers.addAll(msg.getResponseHeader().getHeaderValues(HttpHeader.CACHE_CONTROL));

            for (String directive : headers) {
                for (String directiveToken : directive.split(" ")) {
                    // strip off any trailing comma
                    if (directiveToken.endsWith(","))
                        directiveToken = directiveToken.substring(0, directiveToken.length() - 1);
                    if (logger.isTraceEnabled())
                        logger.trace("Looking for 'no-store' in [" + directiveToken + "]");
                    if (directiveToken.toLowerCase().equals("no-store")) {
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " is not storable due to the use of HTTP caching directive 'no-store' in the request or response");
                        alertNonStorable(msg, id, directiveToken);
                        return;
                    }
                }
            }

            // does the "private" response directive appear in the response, if the cache is shared
            // check the Cache-Control response header only (for HTTP 1.1 caches)
            List<String> responseHeadersCacheControl =
                    msg.getResponseHeader().getHeaderValues(HttpHeader.CACHE_CONTROL);
            if (!responseHeadersCacheControl.isEmpty()) {
                for (String directive : responseHeadersCacheControl) {
                    for (String directiveToken : directive.split(" ")) {
                        // strip off any trailing comma
                        if (directiveToken.endsWith(","))
                            directiveToken =
                                    directiveToken.substring(0, directiveToken.length() - 1);
                        if (logger.isTraceEnabled())
                            logger.trace("Looking for 'private' in [" + directiveToken + "]");
                        if (directiveToken.toLowerCase().equals("private")) {
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " is not storable due to the use of HTTP caching directive 'private' in the response");
                            alertNonStorable(msg, id, directiveToken);
                            return;
                        }
                    }
                }
            }

            // does the Authorization header field appear in the request, if the cache is shared
            // (which we assume it is for now)
            // if so, does the response explicitly allow it to be cached? (see rfc7234 section 3.2)
            // Note: this logic defines if an initial request is storable.  A second request for the
            // same URL
            // may or may not be actually served from the cache, depending on other criteria, such
            // as whether the cached response is
            // considered stale (based on the values of s-maxage and other values).  This is in
            // accordance with rfc7234 section 3.2.
            List<String> authHeaders =
                    msg.getRequestHeader().getHeaderValues(HttpHeader.AUTHORIZATION);
            if (!authHeaders.isEmpty()) {
                // there is an authorization header
                // look for "must-revalidate", "public", and "s-maxage", in the response, since
                // these permit
                // a request with an "Authorization" request header to be cached
                if (!responseHeadersCacheControl.isEmpty()) {
                    boolean authorizedIsStorable = false;
                    for (String directive : responseHeadersCacheControl) {
                        for (String directiveToken : directive.split(" ")) {
                            // strip off any trailing comma
                            if (directiveToken.endsWith(","))
                                directiveToken =
                                        directiveToken.substring(0, directiveToken.length() - 1);
                            if (logger.isTraceEnabled())
                                logger.trace(
                                        "Looking for 'must-revalidate', 'public', 's-maxage' in ["
                                                + directiveToken
                                                + "]");
                            if ((directiveToken.toLowerCase().equals("must-revalidate"))
                                    || (directiveToken.toLowerCase().equals("public"))
                                    || (directiveToken.toLowerCase().startsWith("s-maxage="))) {
                                authorizedIsStorable = true;
                                break;
                            }
                        }
                    }
                    // is the request with an authorisation header allowed, based on the response
                    // headers?
                    if (!authorizedIsStorable) {
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " is not storable due to the use of the 'Authorisation' request header, without a compensatory 'must-revalidate', 'public', or 's-maxage' directive in the response");
                        alertNonStorable(msg, id, HttpHeader.AUTHORIZATION + ":");
                        return;
                    }
                } else {
                    if (logger.isDebugEnabled())
                        logger.debug(
                                msg.getRequestHeader().getURI().getURI()
                                        + " is not storable due to the use of the 'Authorisation' request header, without a compensatory 'must-revalidate', 'public', or 's-maxage' directive in the response (no 'Cache-Control' directive was noted)");
                    alertNonStorable(msg, id, HttpHeader.AUTHORIZATION + ":");
                    return;
                }
            }

            // in addition to the checks above, just one of the following needs to be true for the
            // response to be storable
            /*
            * the response
            *  contains an Expires header field (see Section 5.3), or
            *  contains a max-age response directive (see Section 5.2.2.8), or
            *  contains a s-maxage response directive (see Section 5.2.2.9)
                   and the cache is shared, or
            *  contains a Cache Control Extension (see Section 5.2.3) that
                   allows it to be cached, or
            *  has a status code that is defined as cacheable by default (see
                   Section 4.2.2), or
            *  contains a public response directive (see Section 5.2.2.5).
            */
            // TODO: replace "Expires" with some defined constant. Can't find one right now though.
            // Ho Hum.
            List<String> expires = msg.getResponseHeader().getHeaderValues("Expires");
            if (!expires.isEmpty())
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " *is* storable due to the basic checks, and the presence of the 'Expires' header in the response");
            // grab this for later. Not needed for "storability" checks.
            List<String> dates = msg.getResponseHeader().getHeaderValues("Date");

            String maxAge = null, sMaxAge = null, publicDirective = null;
            if (!responseHeadersCacheControl.isEmpty()) {
                for (String directive : responseHeadersCacheControl) {
                    for (String directiveToken : directive.split(" ")) {
                        // strip off any trailing comma
                        if (directiveToken.endsWith(","))
                            directiveToken =
                                    directiveToken.substring(0, directiveToken.length() - 1);
                        if (logger.isTraceEnabled())
                            logger.trace(
                                    "Looking for 'max-age', 's-maxage', 'public' in ["
                                            + directiveToken
                                            + "]");
                        if (directiveToken.toLowerCase().startsWith("max-age=")) {
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " *is* storable due to the basic checks, and the presence of the 'max-age' caching directive in the response");
                            maxAge = directiveToken;
                        }
                        if (directiveToken
                                .toLowerCase()
                                .startsWith("s-maxage=")) { // for a shared cache..
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " *is* storable due to the basic checks, and the presence of the 's-maxage' caching directive in the response");
                            sMaxAge = directiveToken;
                        }
                        if (directiveToken.toLowerCase().equals("public")) {
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " *is* storable due to the basic checks, and the presence of the 'public' caching directive in the response");
                            publicDirective = directiveToken;
                        }
                    }
                }
            }
            // TODO: implement checks here for known (implementation specific) Cache Control
            // Extensions that would
            // allow the response to be cached.

            // rfc7231 defines the following response codes as cacheable by default
            boolean statusCodeCacheable = false;
            int response = msg.getResponseHeader().getStatusCode();
            if ((response == 200)
                    || (response == 203)
                    || (response == 204)
                    || (response == 206)
                    || (response == 300)
                    || (response == 301)
                    || (response == 404)
                    || (response == 405)
                    || (response == 410)
                    || (response == 414)
                    || (response == 501)) {
                statusCodeCacheable = true;
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " *is* storable due to the basic checks, and the presence of a cacheable response status code (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501)");
            }

            if (expires.isEmpty()
                    && maxAge == null
                    && sMaxAge == null
                    && statusCodeCacheable == false
                    && publicDirective == null) {
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " is not storable due to the absence of any of an 'Expires' header, 'max-age' directive, 's-maxage' directive, 'public' directive, or cacheable response status code (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501) in the response");
                // we raise the alert with the status code as evidence, because all the other
                // conditions are "absent", rather "present" (ie, it is the only possible evidence
                // we can show in this case).
                alertNonStorable(msg, id, String.valueOf(response));
                return;
            }

            // at this point, we *know* that the response is storable.
            // so check if the content is retrievable from the cache (i.e. "cacheable")
            /*
             *   When presented with a request, a cache MUST NOT reuse a stored
             *   response, unless:
             *   o  The presented effective request URI (Section 5.5 of [RFC7230]) and
             *      that of the stored response match, and
             *   o  the request method associated with the stored response allows it
             *      to be used for the presented request, and
             *   o  selecting header fields nominated by the stored response (if any)
             *      match those presented (see Section 4.1), and
             *   o  the presented request does not contain the no-cache pragma
             *      (Section 5.4), nor the no-cache cache directive (Section 5.2.1),
             *      unless the stored response is successfully validated
             *      (Section 4.3), and
             *   o  the stored response does not contain the no-cache cache directive
             *      (Section 5.2.2.2), unless it is successfully validated
             *      (Section 4.3), and
             *   o  the stored response is either:
             *      *  fresh (see Section 4.2), or
             *      *  allowed to be served stale (see Section 4.2.4), or
             *      *  successfully validated (see Section 4.3).
             *   Note that any of the requirements listed above can be overridden by a
             *   cache-control extension; see Section 5.2.3.
             */

            // 1: we assume that the presented effective request URI matches that of the stored
            // response in the cache
            // 2: we assume that the presented request method is compatible with the request method
            // of the stored response
            // 3: we assume that the presented selecting header fields match the selecting header
            // fields nominated by the stored response (if any)
            // 4: we assume that the presented request does not contain the no-cache pragma, nor the
            // no-cache cache directive

            // check if the stored response does not contain the no-cache cache directive, unless it
            // is successfully validated
            // note: we cannot (passively or actively) check the re-validation process, and can only
            // assume that it will properly
            // respond with details of whether the cache server can serve the cached contents or
            // not.  In any event, this decision is made by the origin
            // server, and is not at the discretion of the cache server, so we do not concern
            // ourselves with it here.
            headers = msg.getResponseHeader().getHeaderValues(HttpHeader.CACHE_CONTROL);
            if (!headers.isEmpty()) {
                for (String directive : headers) {
                    for (String directiveToken : directive.split(" ")) {
                        // strip off any trailing comma
                        if (directiveToken.endsWith(","))
                            directiveToken =
                                    directiveToken.substring(0, directiveToken.length() - 1);
                        if (logger.isTraceEnabled())
                            logger.trace("Looking for 'no-cache' in [" + directiveToken + "]");
                        // Note: if the directive looked like "Cache-Control: no-cache #field-name"
                        // (with the optional field name argument, with no comma separating them),
                        // then the "no-cache" directive only applies to the field name (response
                        // header) in question, and not the entire contents.
                        // In this case, the remainder of the contents may be served without
                        // validation.  The logic below is consistent with this requirement.
                        if (directiveToken.toLowerCase().equals("no-cache")) {
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " is not retrievable from the cache (cacheable) due to the use of the unqualified HTTP caching directive 'no-cache' in the response");
                            alertStorableNonCacheable(msg, id, directiveToken);
                            return;
                        }
                    }
                }
            }

            // is the stored response fresh?
            // Note that fresh = freshness lifetime > current age
            long lifetime = -1;
            boolean lifetimeFound = false;
            String freshEvidence = null;
            String otherInfo = null;

            // 1: calculate the freshness lifetime of the request, using the following checks, with
            // the following priority, as specified by rfc7234.
            //	1a:Get the "s-maxage" response directive value (if duplicates exist, the values are
            // invalid)
            if (!responseHeadersCacheControl.isEmpty()) {
                int lifetimesFound = 0;
                for (String directive : responseHeadersCacheControl) {
                    for (String directiveToken : directive.split(" ")) {
                        // strip off any trailing comma
                        if (directiveToken.endsWith(","))
                            directiveToken =
                                    directiveToken.substring(0, directiveToken.length() - 1);
                        if (logger.isTraceEnabled())
                            logger.trace("Looking for 's-maxage' in [" + directiveToken + "]");
                        if (directiveToken.toLowerCase().startsWith("s-maxage=")) {
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " has a caching lifetime defined by an HTTP caching directive 's-maxage' ");
                            lifetimeFound = true;
                            lifetimesFound++;
                            // get the portion of the string after "s-maxage="
                            lifetime =
                                    Long.parseLong(directiveToken.substring("s-maxage=".length()));
                            freshEvidence = directiveToken;
                        }
                    }
                }
                // if duplicates exist, the values are invalid. as per rfc7234.
                if (lifetimesFound > 1) {
                    lifetimeFound = false;
                    lifetime = -1;
                    freshEvidence = null;
                    if (logger.isDebugEnabled())
                        logger.debug(
                                msg.getRequestHeader().getURI().getURI()
                                        + " had multiple caching lifetimes defined by an HTTP caching directive 's-maxage'. Invalidating all of these!");
                }
            }

            //	1b:Get the "max-age" response directive value (if duplicates exist, the values are
            // invalid)
            if (!lifetimeFound) {
                if (!responseHeadersCacheControl.isEmpty()) {
                    int lifetimesFound = 0;
                    for (String directive : responseHeadersCacheControl) {
                        for (String directiveToken : directive.split(" ")) {
                            // strip off any trailing comma
                            if (directiveToken.endsWith(","))
                                directiveToken =
                                        directiveToken.substring(0, directiveToken.length() - 1);
                            if (logger.isTraceEnabled())
                                logger.trace("Looking for 'max-age' in [" + directiveToken + "]");
                            if (directiveToken.toLowerCase().startsWith("max-age=")) {
                                if (logger.isDebugEnabled())
                                    logger.debug(
                                            msg.getRequestHeader().getURI().getURI()
                                                    + " has a caching lifetime defined by an HTTP caching directive 'max-age' ");
                                lifetimeFound = true;
                                lifetimesFound++;
                                // get the portion of the string after "maxage="
                                // Split on comma and use 0th item in case there weren't spaces:
                                // Cache-Control: max-age=7776000,private
                                try {
                                    lifetime =
                                            Long.parseLong(
                                                    directiveToken.split(",")[0].substring(
                                                            "max-age=".length()));
                                } catch (NumberFormatException nfe) {
                                    lifetimeFound = false;
                                    lifetimesFound--;
                                    if (logger.isDebugEnabled()) {
                                        logger.debug(
                                                "Could not parse max-age to establish lifetime. Perhaps the value exceeds Long.MAX_VALUE or contains non-number characters:"
                                                        + directiveToken);
                                    }
                                }
                                freshEvidence = directiveToken;
                            }
                        }
                    }
                    // if duplicates exist, the values are invalid. as per rfc7234.
                    if (lifetimesFound > 1) {
                        lifetimeFound = false;
                        lifetime = -1;
                        freshEvidence = null;
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " had multiple caching lifetimes defined by an HTTP caching directive 'max-age'. Invalidating all of these!");
                    }
                }
            }

            //	1c: Get the "Expires" response header value - "Date" response header field. ("Date"
            // is optional if the origin has no clock, or returned a 1XX or 5XX response, else
            // mandatory)
            if (!lifetimeFound) {
                String expiresHeader = null;
                String dateHeader = null;
                if (!expires.isEmpty()) {
                    // Expires can be absent, or take the form of "Thu, 27 Nov 2014 12:21:57 GMT",
                    // "-1", "0", etc.
                    // Invalid dates are treated as "expired"
                    int expiresHeadersFound = 0;
                    for (String directive : expires) {
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " has a caching lifetime expiry defined by an HTTP response header 'Expires'");
                        expiresHeadersFound++;
                        expiresHeader = directive;
                        freshEvidence = directive;
                    }
                    // if duplicates exist, the values are invalid. as per rfc7234.
                    if (expiresHeadersFound > 1) {
                        expiresHeader = null;
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " had multiple caching lifetime expirys defined by an HTTP response header 'Expires'. Invalidating all of these!");
                    } else {
                        // we now have a single "expiry".
                        // Now it is time to get the "date" for the request, so we can subtract the
                        // "date" from the "expiry" to get the "lifetime".
                        if (!dates.isEmpty()) {
                            int dateHeadersFound = 0;
                            for (String directive : dates) {
                                if (logger.isDebugEnabled())
                                    logger.debug(
                                            msg.getRequestHeader().getURI().getURI()
                                                    + " has a caching lifetime date defined by an HTTP response header 'Date'");
                                dateHeadersFound++;
                                dateHeader = directive;
                            }
                            // if duplicates exist, the values are invalid. as per rfc7234.
                            if (dateHeadersFound > 1) {
                                dateHeader = null;
                                if (logger.isDebugEnabled())
                                    logger.debug(
                                            msg.getRequestHeader().getURI().getURI()
                                                    + " had multiple caching lifetime dates defined by an HTTP response header 'Date'. Invalidating all of these!");
                            } else {
                                // we have one expiry, and one date. Yippee.. Are they valid tough??
                                // both dates can be invalid, or have one of 3 formats, all of which
                                // MUST be supported!
                                Date expiresDate = parseDate(expiresHeader);

                                if (expiresDate != null) {
                                    Date dateDate = parseDate(dateHeader);
                                    if (dateDate != null) {
                                        // calculate the lifetime = Expires - Date
                                        lifetimeFound = true;
                                        lifetime =
                                                (expiresDate.getTime() - dateDate.getTime()) / 1000;
                                        // there is multiple parts to the evidence in this case (the
                                        // Expiry, and the Date, but lets show the Expiry)
                                        freshEvidence = expiresHeader;
                                        if (logger.isDebugEnabled())
                                            logger.debug(
                                                    msg.getRequestHeader().getURI().getURI()
                                                            + " had an 'Expires' date and a 'Date' date, which were used to calculate the lifetime of the request");
                                    } else {
                                        // the "Date" date is not valid. Treat it as "expired"
                                        if (logger.isDebugEnabled())
                                            logger.debug(
                                                    msg.getRequestHeader().getURI().getURI()
                                                            + " had an invalid caching lifetime date defined by an HTTP response header 'Date'. Ignoring the 'Expires' header for the purposes of lifetime calculation.");
                                        lifetime = -1;
                                    }
                                } else {
                                    // the expires date is not valid. Treat it as "expired"
                                    // (will not result in a "cacheable" alert, so the evidence is
                                    // not needed, in fact
                                    if (logger.isDebugEnabled())
                                        logger.debug(
                                                msg.getRequestHeader().getURI().getURI()
                                                        + " had an invalid caching lifetime expiry date defined by an HTTP response header 'Expiry'. Assuming an historic/ expired lifetime.");
                                    lifetimeFound = true;
                                    lifetime = 0;
                                    freshEvidence = expiresHeader;
                                }
                            }
                        } else {
                            // "Dates" is not defined. Nothing to do!
                            if (logger.isDebugEnabled())
                                logger.debug(
                                        msg.getRequestHeader().getURI().getURI()
                                                + " has a caching lifetime expiry defined by an HTTP response header 'Expires', but no 'Date' header to subtract from it");
                        }
                    }
                } else {
                    // "Expires" is not defined. Nothing to do!
                    if (logger.isDebugEnabled())
                        logger.debug(
                                msg.getRequestHeader().getURI().getURI()
                                        + " has no caching lifetime expiry defined by an HTTP response header 'Expires'");
                }
            }

            //	1d: Use a heuristic to determine a "plausible" expiration time.  This is
            // implementation specific, and the implementation is permitted to be liberal.
            //  for the purposes of this exercise, lets assume the cache chooses a "plausible"
            // expiration of 1 year (expressed in seconds)
            if (!lifetimeFound) {
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " has no caching lifetime expiry of any form, so assuming that it is set 'heuristically' to 1 year (as a form of worst case)");
                lifetimeFound = true;
                lifetime = 60 * 60 * 24 * 365;
                // a liberal heuristic was assumed, for which no actual evidence exists
                freshEvidence = null;
                otherInfo =
                        Constant.messages.getString(
                                MESSAGE_PREFIX_STORABLE_CACHEABLE
                                        + "otherinfo.liberallifetimeheuristic");
            }

            if (logger.isDebugEnabled())
                logger.debug(
                        msg.getRequestHeader().getURI().getURI()
                                + " has a caching lifetime of "
                                + lifetime);

            // 2: calculate the current age of the request
            //   Note that since we are not necessarily testing via a cache, the "Age" header may
            // not be set (this is set by the caching server, not by the web server)
            //   so we can only possibly get the "apparent_age", and not the "corrected_age_value"
            // documented in rfc7234.
            //   In any event, this is not an issue, because in the worst case, the user could be
            // sending the first request for a given URL, placing
            //   the response in the cache, with an age approaching 0 (depending on network delay).
            //   By this logic, let's not even try to check the "apparent_age" (since it depends on
            // our network, and could be completely different for other users)
            //   and let's assume that in at least some cases, the "age" can be 0 (the most extreme
            // case, from the point of view of "freshness").
            //   so "freshness" depends purely on the defined lifetime, in practice.
            long age = 0;

            // so after all that, is the response fresh or not?
            if (lifetime > age) {
                // fresh, so it can be retrieved from the cache
                if (logger.isDebugEnabled())
                    logger.debug(
                            msg.getRequestHeader().getURI().getURI()
                                    + " is retrievable from the cache (cacheable), since it is fresh");
                alertStorableCacheable(msg, id, freshEvidence, otherInfo);
                return;
            } else {
                // stale!
                // is the stored response allowed to be served stale?
                // if the following are not present, the response *can* be served stale..
                // Note: this area of the RFC is vague at best (and somewhat contradictory), so this
                // area may need to be reviewed once the RFC has been updated
                // (the version used is rfc7234 from June 2014)
                /*
                "must-revalidate" 	- OK (fairly explicit)
                "proxy-revalidate"	- OK (fairly explicit)
                "s-maxage"			- see rfc7234, section 3.2
                "max-age"			- inferred, based on the case for "s-maxage"
                */

                boolean staleRetrieveAllowed = true;
                String doNotRetrieveStaleEvidence = null;
                if (!responseHeadersCacheControl.isEmpty()) {
                    for (String directive : responseHeadersCacheControl) {
                        for (String directiveToken : directive.split(" ")) {
                            // strip off any trailing comma
                            if (directiveToken.endsWith(","))
                                directiveToken =
                                        directiveToken.substring(0, directiveToken.length() - 1);
                            if (logger.isTraceEnabled())
                                logger.trace(
                                        "Looking for 'must-revalidate', 'proxy-revalidate', 's-maxage', 'max-age' in ["
                                                + directiveToken
                                                + "]");
                            if ((directiveToken.toLowerCase().equals("must-revalidate"))
                                    || (directiveToken.toLowerCase().equals("proxy-revalidate"))
                                    || (directiveToken.toLowerCase().startsWith("s-maxage="))
                                    || (directiveToken.toLowerCase().startsWith("max-age="))) {
                                staleRetrieveAllowed = false;
                                doNotRetrieveStaleEvidence = directiveToken;
                                break;
                            }
                        }
                    }
                }
                // TODO: check for any known Cache Control Extensions here, before making a final
                // call on the retrievability of the cached data.
                if (staleRetrieveAllowed) {
                    // no directives were configured to prevent stale responses being retrieved
                    // (without validation)
                    alertStorableCacheable(
                            msg,
                            id,
                            "",
                            Constant.messages.getString(
                                    MESSAGE_PREFIX_STORABLE_CACHEABLE
                                            + "otherinfo.staleretrievenotblocked"));
                } else {
                    // the directives do not allow stale responses to be retrieved
                    // we saw just one other scenario where this could happen: where the response
                    // was cached, but the "no-cache" response directive was specified
                    alertStorableNonCacheable(msg, id, doNotRetrieveStaleEvidence);
                }
            }
        } catch (Exception e) {
            logger.error(
                    "An error occurred while checking a URI [ "
                            + msg.getRequestHeader().getURI().toString()
                            + " ] for cacheability",
                    e);
        }
    }

    private Date parseDate(String dateStr) {
        Date newDate = null;
        try {
            newDate = DateUtil.parseDate(dateStr);
        } catch (DateParseException dpe) {
            // There was an error parsing the date, leave the var null
        }
        return newDate;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX_STORABILITY_CACHEABILITY + "name");
    }

    /**
     * raise an alert for a non-storable response
     *
     * @param msg
     * @param id
     * @param evidence
     */
    public void alertNonStorable(HttpMessage msg, int id, String evidence) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX_NONSTORABLE + "name"))
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX_NONSTORABLE + "desc"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX_NONSTORABLE + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX_NONSTORABLE + "refs"))
                .setEvidence(evidence)
                .setCweId(524) // CWE-524: Information Exposure Through Caching
                .setWascId(13) // WASC-13: Information Leakage
                .raise();
    }

    /**
     * raise an alert for a storable but non-cacheable response
     *
     * @param msg
     * @param id
     * @param evidence
     */
    public void alertStorableNonCacheable(HttpMessage msg, int id, String evidence) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX_STORABLE_NONCACHEABLE + "name"))
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_NONCACHEABLE + "desc"))
                .setSolution(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_NONCACHEABLE + "soln"))
                .setReference(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_NONCACHEABLE + "refs"))
                .setEvidence(evidence)
                .setCweId(524) // CWE-524: Information Exposure Through Caching
                .setWascId(13) // WASC-13: Information Leakage
                .raise();
    }

    /**
     * raise an alert for a storable and cacheable (retrievable from the cache) response
     *
     * @param msg
     * @param id
     * @param evidence
     * @param otherInfo
     */
    public void alertStorableCacheable(HttpMessage msg, int id, String evidence, String otherInfo) {
        newAlert()
                .setName(Constant.messages.getString(MESSAGE_PREFIX_STORABLE_CACHEABLE + "name"))
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_CACHEABLE + "desc"))
                .setOtherInfo(otherInfo)
                .setSolution(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_CACHEABLE + "soln"))
                .setReference(
                        Constant.messages.getString(MESSAGE_PREFIX_STORABLE_CACHEABLE + "refs"))
                .setEvidence(evidence)
                .setCweId(524) // CWE-524: Information Exposure Through Caching
                .setWascId(13) // WASC-13: Information Leakage
                .raise();
    }
}
