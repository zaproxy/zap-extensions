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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.List;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Detect content that has been served from a shared cache.
 *
 * @author 70pointer@gmail.com
 */
public class RetrievedFromCacheScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.retrievedfromcache.";
    private static final int PLUGIN_ID = 10050;

    private static final Logger logger = Logger.getLogger(RetrievedFromCacheScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        try {
            if (logger.isDebugEnabled())
                logger.debug(
                        "Checking URL "
                                + msg.getRequestHeader().getURI().getURI()
                                + " to see if was served from a shared cache");

            // X-Cache: HIT
            // X-Cache: HIT from cache.kolich.local					<-- was the data actually served from the
            // cache (subject to no-cache, expiry, etc.)?
            //															(if X-Cache: HIT, it implies X-Cache-Lookup: HIT)
            //															(and if X-Cache-Lookup: MISS, it implies X-Cache: MISS)
            // X-Cache-Lookup: HIT from cache.kolich.local:80		<-- was the data *available* in the
            // cache? (not whether it was actually served)

            // X-Cache: MISS
            // X-Cache: MISS from cache.kolich.local
            // X-Cache-Lookup: MISS from cache.kolich.local:80

            // X-Cache HIT from proxy.domain.tld, MISS from proxy.local
            // X-Cache-Lookup HIT from proxy.domain.tld:3128, MISS from proxy.local:3128

            List<String> xcacheHeaders = msg.getResponseHeader().getHeaderValues("X-Cache");
            if (!xcacheHeaders.isEmpty()) {
                for (String xcacheHeader : xcacheHeaders) {
                    for (String proxyServerDetails : xcacheHeader.split(",")) {
                        // strip off any leading space for the second and subsequent proxies
                        if (proxyServerDetails.startsWith(" "))
                            proxyServerDetails = proxyServerDetails.substring(1);
                        if (logger.isTraceEnabled())
                            logger.trace("Proxy HIT/MISS details [" + proxyServerDetails + "]");
                        String[] proxyServerDetailsArray = proxyServerDetails.split(" ", 3);
                        if (proxyServerDetailsArray.length >= 1) {
                            String hitormiss =
                                    proxyServerDetailsArray[0].toUpperCase(); // HIT or MISS
                            if (hitormiss.equals("HIT")) {
                                // the response was served from cache, so raise it..
                                String evidence = proxyServerDetails;
                                if (logger.isDebugEnabled())
                                    logger.debug(
                                            msg.getRequestHeader().getURI().getURI()
                                                    + " was served from a cache, due to presence of a 'HIT' in the 'X-Cache' response header");
                                // could be from HTTP/1.0 or HTTP/1.1. We don't know which.
                                newAlert()
                                        .setRisk(Alert.RISK_INFO)
                                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                        .setDescription(getDescription())
                                        .setSolution(getSolution())
                                        .setReference(getReference())
                                        .setEvidence(evidence)
                                        .raise();
                                return;
                            }
                        }
                    }
                }
            }

            // The "Age" header (defined in RFC 7234) conveys the sender's estimate of the amount of
            // time since the response (or its revalidation) was generated at the origin server.
            // An HTTP/1.1 server that includes a cache MUST include an Age header field in every
            // response generated from its own cache.
            // i.e.: a valid "Age" header implies that the response was served from a cache
            // lets validate that it is actually a non-negative decimal integer, as mandated by RFC
            // 7234, however.
            // if there are multiple "Age" headers, just look for one valid value in the multiple
            // "Age" headers.. Not sure if this case is strictly valid with the spec, however.
            // Note: HTTP/1.0 caches do not implement "Age", so the absence of an "Age" header does
            // *not* imply that the response was served from the origin server, rather than a
            // cache..
            List<String> ageHeaders = msg.getResponseHeader().getHeaderValues("Age");
            if (!ageHeaders.isEmpty()) {
                for (String ageHeader : ageHeaders) {
                    if (logger.isTraceEnabled())
                        logger.trace("Validating Age header value [" + ageHeader + "]");
                    Long ageAsLong = Long.parseLong(ageHeader);
                    if (ageAsLong != null && ageAsLong >= 0) {
                        String evidence = "Age: " + ageHeader;
                        if (logger.isDebugEnabled())
                            logger.debug(
                                    msg.getRequestHeader().getURI().getURI()
                                            + " was served from a HTTP/1.1 cache, due to presence of a valid (non-negative decimal integer) 'Age' response header value");
                        newAlert()
                                .setRisk(Alert.RISK_INFO)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setDescription(getDescription())
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX
                                                        + "extrainfo.http11ageheader")) // Other
                                // info:
                                // "Age"
                                // header implies a
                                // HTTP/1.1
                                // compliant cache
                                // server.
                                .setSolution(getSolution())
                                .setReference(getReference())
                                .setEvidence(evidence)
                                .raise();
                        return;
                    }
                }
            }

        } catch (Exception e) {
            logger.error("An error occurred while checking if a URL was served from a cache", e);
        }
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

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
}
