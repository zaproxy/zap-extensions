/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Big Redirects passive scan rule https://github.com/zaproxy/zaproxy/issues/1257 */
public class BigRedirectsScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "pscanrules.bigredirects.";
    private static final int PLUGIN_ID = 10044;

    private static final Logger LOGGER = LogManager.getLogger(BigRedirectsScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED,
                    CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK);

    private static final Pattern HREF_PATTERN = Pattern.compile("href", Pattern.CASE_INSENSITIVE);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        // isRedirect checks response code between 300 and 400, but 304 isn't actually a redirect
        // it's "not modified"
        if (HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode())
                && msg.getResponseHeader().getStatusCode() != 304) { // This response is a redirect
            int responseLocationHeaderURILength = 0;
            String locationHeaderValue = msg.getResponseHeader().getHeader(HttpHeader.LOCATION);
            if (locationHeaderValue != null) {
                responseLocationHeaderURILength = locationHeaderValue.length();
            } else { // No location header found
                LOGGER.debug(
                        "Though the response had a redirect status code it did not have a Location header.\nRequested URL: {}",
                        msg.getRequestHeader().getURI());
            }

            if (responseLocationHeaderURILength > 0) {
                int predictedResponseSize =
                        getPredictedResponseSize(responseLocationHeaderURILength);
                int responseBodyLength = msg.getResponseBody().length();
                // Check if response is bigger than predicted
                if (responseBodyLength > predictedResponseSize) {
                    // Response is larger than predicted so raise an alert
                    createBigAlert(
                                    responseLocationHeaderURILength,
                                    locationHeaderValue,
                                    predictedResponseSize,
                                    responseBodyLength)
                            .raise();
                } else {
                    Matcher matcher = HREF_PATTERN.matcher(msg.getResponseBody().toString());
                    long hrefCount = matcher.results().count();
                    if (hrefCount > 1) {
                        createMultiAlert(hrefCount).raise();
                    }
                }
            }
        }
        LOGGER.debug("\tScan of record {} took {}ms", id, System.currentTimeMillis() - start);
    }

    /**
     * Gets the predicted size of the response body based on the URI specified in the response's
     * Location header
     *
     * @param redirectURILength the length of the URI in the redirect response Location header
     * @return predictedResponseSize
     */
    private int getPredictedResponseSize(int redirectURILength) {
        int predictedResponseSize = redirectURILength + 300;
        LOGGER.debug("Original Response Location Header URI Length: {}", redirectURILength);
        LOGGER.debug("Predicted Response Size: {}", predictedResponseSize);
        return predictedResponseSize;
    }

    private AlertBuilder createBaseAlert(String ref) {
        return newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setSolution(getSolution())
                .setCweId(201)
                .setWascId(13)
                .setAlertRef(String.valueOf(PLUGIN_ID) + ref);
    }

    private AlertBuilder createBigAlert(
            int urlLength, String url, int predictedMaxLength, int actualMaxLength) {
        return createBaseAlert("-1")
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "extrainfo",
                                urlLength,
                                url,
                                predictedMaxLength,
                                actualMaxLength));
    }

    private AlertBuilder createMultiAlert(long hrefCount) {
        return createBaseAlert("-2")
                .setName(Constant.messages.getString(MESSAGE_PREFIX + "multi.name"))
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "multi.desc"))
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + "multi.extrainfo", hrefCount));
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createBigAlert(18, "http://example.com", 318, 319).build(),
                createMultiAlert(3).build());
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
