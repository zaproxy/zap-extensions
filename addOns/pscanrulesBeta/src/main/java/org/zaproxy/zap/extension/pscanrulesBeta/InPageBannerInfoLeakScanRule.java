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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * In Page Banner Information Leak passive scan rule https://github.com/zaproxy/zaproxy/issues/178
 */
public class InPageBannerInfoLeakScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    private static final Logger LOGGER = LogManager.getLogger(InPageBannerInfoLeakScanRule.class);
    private static final int PLUGIN_ID = 10009;
    private static final String MESSAGE_PREFIX = "pscanbeta.inpagebanner.";
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        int statusCode = msg.getResponseHeader().getStatusCode();
        // If LOW and 200 then check or if isClientError or isServerError check
        if ((this.getAlertThreshold().equals(AlertThreshold.LOW)
                        && (HttpStatusCode.isSuccess(statusCode) || getHelper().isPage200(msg)))
                || (getHelper().isClientError(msg) || getHelper().isServerError(msg))) {
            for (BannerPattern patt : BannerPattern.values()) {
                Matcher bannerMatcher = patt.getPattern().matcher(msg.getResponseBody().toString());
                boolean found = bannerMatcher.find();
                if (found) {
                    createAlert(bannerMatcher.group()).raise();
                    break;
                }
            }
        }
        LOGGER.debug("\tScan of record {} took {} ms", id, System.currentTimeMillis() - start);
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private AlertBuilder createAlert(String evidence) {
        return newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "other"))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(evidence) // Evidence - Return the in page banner
                .setCweId(200) // CWE Id: 200 - Information Exposure
                .setWascId(13); // WASC Id: 13 - Information Leakage
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert("Squid/2.5").build());
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
