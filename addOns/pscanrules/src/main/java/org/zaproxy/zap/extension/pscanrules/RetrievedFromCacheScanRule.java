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
package org.zaproxy.zap.extension.pscanrules;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Detect content that has been served from a shared cache.
 *
 * @author 70pointer@gmail.com
 */
public class RetrievedFromCacheScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.retrievedfromcache.";
    private static final int PLUGIN_ID = 10050;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS);

    private static final Logger LOGGER = LogManager.getLogger(RetrievedFromCacheScanRule.class);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        try {
            LOGGER.debug(
                    "Checking URL {} to see if was served from a shared cache",
                    msg.getRequestHeader().getURI());

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
                        LOGGER.trace("Proxy HIT/MISS details [{}]", proxyServerDetails);
                        String[] proxyServerDetailsArray = proxyServerDetails.split(" ", 3);
                        if (proxyServerDetailsArray.length >= 1) {
                            String hitormiss =
                                    proxyServerDetailsArray[0].toUpperCase(); // HIT or MISS
                            if (hitormiss.equals("HIT")) {
                                // the response was served from cache, so raise it..
                                String evidence = proxyServerDetails;
                                LOGGER.debug(
                                        "{} was served from a cache, due to presence of a 'HIT' in the 'X-Cache' response header",
                                        msg.getRequestHeader().getURI());
                                // could be from HTTP/1.0 or HTTP/1.1. We don't know which.
                                buildAlert(evidence, false).raise();
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
                    LOGGER.trace("Validating Age header value [{}]", ageHeader);
                    Long ageAsLong = null;
                    try {
                        ageAsLong = Long.parseLong(ageHeader);
                    } catch (NumberFormatException nfe) {
                        // Ignore
                    }
                    if (ageAsLong != null && ageAsLong >= 0) {
                        String evidence = "Age: " + ageHeader;
                        LOGGER.debug(
                                "{} was served from a HTTP/1.1 cache, due to presence of a valid (non-negative decimal integer) 'Age' response header value",
                                msg.getRequestHeader().getURI());
                        buildAlert(evidence, true).raise();
                        return;
                    }
                }
            }

        } catch (Exception e) {
            LOGGER.error("An error occurred while checking if a URL was served from a cache", e);
        }
    }

    private AlertBuilder buildAlert(String evidence, boolean compliant) {
        return newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                // If compliant Other Info: "Age" header implies a HTTP/1.1 compliant cache server.
                .setOtherInfo(
                        compliant
                                ? Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.http11ageheader")
                                : "")
                .setAlertRef(PLUGIN_ID + (compliant ? "-2" : "-1"));
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

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                buildAlert("X-Cache: HIT, HIT", false).build(),
                buildAlert("Age: 24", true).build());
    }
}
