/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class Spring4ShellScanRule extends AbstractAppPlugin {

    private static final int PLUGIN_ID = 40045;

    protected static final String ATTACK =
            "class.module.classLoader.DefaultAssertionStatus=nonsense";
    private static final String SAFE_PAYLOAD = "aaa=bbb";

    private static final Logger LOG = LogManager.getLogger(Spring4ShellScanRule.class);

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                    CommonAlertTag.OWASP_2017_A01_INJECTION,
                    CommonAlertTag.OWASP_2017_A09_VULN_COMP,
                    CommonAlertTag.WSTG_V42_INPV_12_COMMAND_INJ);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanalpha.spring4shell.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanalpha.spring4shell.desc");
    }

    private boolean is400Response(HttpMessage msg) {
        return !msg.getResponseHeader().isEmpty() && msg.getResponseHeader().getStatusCode() == 400;
    }

    private void setGetPayload(HttpMessage msg, String payload) throws URIException {
        msg.getRequestHeader().setMethod("GET");
        URI uri = msg.getRequestHeader().getURI();
        String query = uri.getEscapedQuery();
        if (query == null) {
            query = payload;
        } else {
            query += "&" + payload;
        }
        uri.setEscapedQuery(query);
    }

    private void setPostPayload(HttpMessage msg, String payload) {
        msg.getRequestHeader().setMethod("POST");
        String body = msg.getRequestBody().toString();
        if (body.isEmpty()
                || !HttpHeader.FORM_URLENCODED_CONTENT_TYPE.equals(
                        msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE))) {
            // If its not FORM_URLENCODED_CONTENT_TYPE then replace the whole body
            body = payload;
        } else {
            body += "&" + payload;
        }
        msg.setRequestBody(body);
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
    }

    private boolean isVulnerable(boolean isGet, String attack) {
        HttpMessage msg = getNewMsg();
        try {
            if (isGet) {
                setGetPayload(msg, attack);
            } else {
                setPostPayload(msg, attack);
            }
            sendAndReceive(msg);
            if (is400Response(msg)) {
                // Looks promising, check a "safe" payload
                HttpMessage safeMsg = getNewMsg();
                if (isGet) {
                    setGetPayload(safeMsg, SAFE_PAYLOAD);
                } else {
                    setPostPayload(safeMsg, SAFE_PAYLOAD);
                }
                sendAndReceive(safeMsg);
                if (!is400Response(safeMsg)) {
                    // The safe payload was fine, so this looks like it really is vulnerable
                    String evidence = msg.getResponseHeader().toString().split(HttpHeader.CRLF)[0];
                    buildAlert().setMessage(msg).setAttack(attack).setEvidence(evidence).raise();
                    return true;
                }
            }
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return false;
    }

    @Override
    public void scan() {
        if (!is400Response(getBaseMsg())) {
            // Try payload with a GET
            if (isVulnerable(true, ATTACK)) {
                return;
            }
            // Try payload with a POST
            isVulnerable(false, ATTACK);
        }
    }

    private AlertBuilder buildAlert() {
        return newAlert().setRisk(Alert.RISK_HIGH).setConfidence(Alert.CONFIDENCE_MEDIUM);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return Arrays.asList(buildAlert().build());
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includesAny(Tech.SPRING);
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 78; // OS Command Injection
    }

    @Override
    public int getWascId() {
        return 20; // Improper Input Handling
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanalpha.spring4shell.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanalpha.spring4shell.refs");
    }
}
