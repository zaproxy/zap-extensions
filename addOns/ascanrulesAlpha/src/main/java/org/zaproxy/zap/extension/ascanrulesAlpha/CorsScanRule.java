/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * The CORS scan rule identifies Cross-Origin Resource Sharing (CORS) support and overly lenient or
 * buggy implementations
 *
 * @author CravateRouge
 */
public class CorsScanRule extends AbstractAppPlugin {
    private static final Logger LOG = LogManager.getLogger(CorsScanRule.class);
    private static final String RANDOM_NAME = RandomStringUtils.random(8, true, true);
    private static final String ACAC = "Access-Control-Allow-Credentials";
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                    CommonAlertTag.WSTG_V42_CLNT_07_CORS);

    @Override
    public void scan() {
        URI uri = getBaseMsg().getRequestHeader().getURI();
        String authority = uri.getEscapedAuthority();
        String scheme = uri.getScheme();
        String handyScheme = scheme + "://";

        // Order of likelihood and severity
        String[] payloads = {
            handyScheme + RANDOM_NAME + ".com",
            "null",
            handyScheme + RANDOM_NAME + "." + authority,
            handyScheme + authority + "." + RANDOM_NAME + ".com",
            // URL encoded backtick used to bypass weak Regex matching only alphanumeric chars to
            // validate the domain: https://www.corben.io/tricky-CORS/
            handyScheme + authority + "%60" + RANDOM_NAME + ".com",
            null,
            handyScheme + authority
        };

        boolean secScheme = false;
        if ("https".equals(scheme)) {
            secScheme = true;
            payloads[5] = "http://" + authority;
        }

        for (String payload : payloads) {
            HttpMessage msg = getNewMsg();
            msg.getRequestHeader().setHeader(HttpRequestHeader.ORIGIN, payload);
            try {
                sendAndReceive(msg);

                HttpResponseHeader respHead = msg.getResponseHeader();
                String acaoVal = respHead.getHeader(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN);

                // If there is an ACAO header an alert will be triggered
                if (acaoVal == null) {
                    continue;
                }

                int risk = Alert.RISK_INFO;
                String acacVal = respHead.getHeader(ACAC);
                acacVal = acacVal == null ? "" : acacVal;

                // Evaluates the risk for this alert
                if (acaoVal.contains("*")) {
                    risk = Alert.RISK_MEDIUM;
                } else if (acaoVal.contains(RANDOM_NAME)
                        || acaoVal.contains("null")
                        || (secScheme && acaoVal.contains("http:"))) {
                    // If authenticated AJAX requests are allowed, the risk is higher
                    risk = acacVal.isEmpty() ? Alert.RISK_MEDIUM : Alert.RISK_HIGH;
                }
                Matcher m =
                        Pattern.compile(
                                        String.format(
                                                "^\\s*%s[:\\s]+%s(\\s+%s[:\\s]+%s)?",
                                                HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN,
                                                Pattern.quote(acaoVal),
                                                ACAC,
                                                acacVal),
                                        Pattern.MULTILINE)
                                .matcher(respHead.toString());
                buildAlert(risk)
                        .setMessage(msg)
                        .setAttack(HttpRequestHeader.ORIGIN + ": " + payload)
                        .setEvidence(m.find() ? m.group(0) : null)
                        .raise();
                return;
            } catch (IOException e) {
                LOG.warn(e.getMessage(), e);
            }
        }
    }

    private AlertBuilder buildAlert(int risk) {
        return newAlert()
                .setName(risk == Alert.RISK_INFO ? getName() : getConstantStr("vuln.name"))
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setDescription(
                        risk == Alert.RISK_INFO ? getDescription() : getConstantStr("vuln.desc"));
    }

    private static String getConstantStr(String suffix) {
        return Constant.messages.getString("ascanalpha.cors." + suffix);
    }

    @Override
    public int getId() {
        return 40040;
    }

    @Override
    public String getName() {
        return getConstantStr("info.name");
    }

    @Override
    public String getDescription() {
        return getConstantStr("info.desc");
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return getConstantStr("soln");
    }

    @Override
    public String getReference() {
        return getConstantStr("refs");
    }

    @Override
    public int getCweId() {
        return 942;
    }

    @Override
    public int getWascId() {
        return 14;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        for (int i = Alert.RISK_INFO; i <= Alert.RISK_HIGH; i++) {
            if (i != Alert.RISK_LOW) {
                alerts.add(buildAlert(i).build());
            }
        }
        return alerts;
    }
}
