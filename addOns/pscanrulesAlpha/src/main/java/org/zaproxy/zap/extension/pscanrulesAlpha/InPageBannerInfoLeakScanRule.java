/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * In Page Banner Information Leak passive scan rule https://github.com/zaproxy/zaproxy/issues/178
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class InPageBannerInfoLeakScanRule extends PluginPassiveScanner {

    private static final Logger LOGGER = Logger.getLogger(InPageBannerInfoLeakScanRule.class);
    private static final int PLUGIN_ID = 10009;
    private static final String MESSAGE_PREFIX = "pscanalpha.inpagebanner.";

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
        long start = System.currentTimeMillis();

        int statusCode = msg.getResponseHeader().getStatusCode();
        // If LOW and 200 then check or if isClientError or isServerError check
        if ((this.getAlertThreshold().equals(AlertThreshold.LOW)
                        && HttpStatusCode.isSuccess(statusCode))
                || (HttpStatusCode.isClientError(statusCode)
                        || HttpStatusCode.isServerError(statusCode))) {
            for (BannerPattern patt : BannerPattern.values()) {
                Matcher bannerMatcher = patt.getPattern().matcher(msg.getResponseBody().toString());
                boolean found = bannerMatcher.find();
                if (found) {
                    raiseAlert(
                            Alert.RISK_LOW, Alert.CONFIDENCE_HIGH, bannerMatcher.group(), msg, id);
                    break;
                }
            }
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
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

    private void raiseAlert(int risk, int confidence, String evidence, HttpMessage msg, int id) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "other"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence) // Evidence - Return the in page banner
                .setCweId(200) // CWE Id: 200 - Information Exposure
                .setWascId(13) // WASC Id: 13 - Information Leakage
                .raise();
    }

    public enum BannerPattern {
        TOMCAT_PATTERN(Pattern.compile("Tomcat\\/\\d\\.\\d\\.\\d{1,2}", Pattern.CASE_INSENSITIVE)),
        APACHE_PATTERN(Pattern.compile("Apache\\/\\d\\.\\d\\.\\d{1,2}", Pattern.CASE_INSENSITIVE)),
        NGINX_PATTERN(
                Pattern.compile("nginx\\/\\d\\.\\d{1,2}\\.\\d{1,2}", Pattern.CASE_INSENSITIVE)),
        JETTY_PATTERN(Pattern.compile("Jetty:\\/\\/\\d\\.\\d{1,2}", Pattern.CASE_INSENSITIVE)),
        SQUID_PATTERN(Pattern.compile("squid\\/\\d\\.\\d{1,2}", Pattern.CASE_INSENSITIVE));

        private Pattern pattern;

        private BannerPattern(Pattern pattern) {
            this.pattern = pattern;
        }

        public Pattern getPattern() {
            return pattern;
        }
    }
}
