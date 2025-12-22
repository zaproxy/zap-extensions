/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class React2ShellScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    private static final Logger LOGGER = LogManager.getLogger(React2ShellScanRule.class);

    private static final String MESSAGE_PREFIX = "ascanrules.react2shell.";

    private static final String EVIDENCE = "E{\"digest\"";

    private static final Map<String, String> ALERT_TAGS;

    public static final Tech Framework =
            new Tech("Framework", MESSAGE_PREFIX + "technologies.framework");
    public static final Tech REACT = new Tech(Framework, "React");
    public static final Tech NEXT_JS = new Tech(Framework, "Next.js");

    private static final String STATE_TREE =
            "[\"\",{\"children\":[\"__PAGE__\",{},null,null]},null,null,true]";
    private static final String BOUNDRY = "----" + UUID.randomUUID();
    private static final String ATTACK = "[\"$1:a:a\"]";

    private static final String PAYLOAD =
            "--"
                    + BOUNDRY
                    + HttpHeader.CRLF
                    + "Content-Disposition: form-data; name=\"1\""
                    + HttpHeader.CRLF
                    + HttpHeader.CRLF
                    + "{}"
                    + HttpHeader.CRLF
                    + "--"
                    + BOUNDRY
                    + HttpHeader.CRLF
                    + "Content-Disposition: form-data; name=\"0\""
                    + HttpHeader.CRLF
                    + HttpHeader.CRLF
                    + ATTACK
                    + HttpHeader.CRLF
                    + "--"
                    + BOUNDRY
                    + "--"
                    + HttpHeader.CRLF;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A03_INJECTION,
                                CommonAlertTag.OWASP_2017_A01_INJECTION,
                                CommonAlertTag.HIPAA,
                                CommonAlertTag.PCI_DSS));

        alertTags.put(PolicyTag.DEV_CICD.getTag(), "");
        alertTags.put(PolicyTag.DEV_FULL.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.QA_CICD.getTag(), "");
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");

        CommonAlertTag.putCve(alertTags, "CVE-2025-55182");
        CommonAlertTag.putCve(alertTags, "CVE-2025-66478");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);

        Tech.add(Framework);
        Tech.add(REACT);
        Tech.add(NEXT_JS);
    }

    @Override
    public int getId() {
        return 40048;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
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
    public void init() {}

    @Override
    public void scan() {
        HttpMessage msg = getNewMsg();
        try {
            HttpRequestHeader reqHeader = msg.getRequestHeader();
            reqHeader.setMethod(HttpRequestHeader.POST);
            reqHeader.addHeader("Next-Action", "x");
            reqHeader.addHeader(
                    "Next-Router-State-Tree",
                    URLEncoder.encode(STATE_TREE, StandardCharsets.UTF_8));
            reqHeader.addHeader("Content-Type", "multipart/form-data; boundary=" + BOUNDRY);

            msg.getRequestBody().setBody(PAYLOAD);
            reqHeader.setContentLength(msg.getRequestBody().length());

            sendAndReceive(msg, false);

            if (msg.getResponseHeader().getStatusCode() == 500
                    && msg.getResponseBody().toString().contains(EVIDENCE)) {
                this.createAlert(msg).raise();
            }
        } catch (Exception e) {
            LOGGER.debug(
                    "Error sending request to {}: {}",
                    msg.getRequestHeader().getURI(),
                    e.getMessage(),
                    e);
        }
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(REACT) || technologies.includes(NEXT_JS);
    }

    private AlertBuilder createAlert(HttpMessage msg) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setAttack(ATTACK)
                .setEvidence(EVIDENCE)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo"))
                .setMessage(msg);
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 78;
    }

    @Override
    public int getWascId() {
        return 32;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert(null).build());
    }
}
