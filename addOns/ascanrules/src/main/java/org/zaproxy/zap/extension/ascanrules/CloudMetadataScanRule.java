/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * Attempts to retrieve cloud metadata by forging the host header and requesting a specific URL. See
 * https://www.nginx.com/blog/trust-no-one-perils-of-trusting-user-input/ for more details
 */
public class CloudMetadataScanRule extends AbstractHostPlugin implements CommonActiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.cloudmetadata.";

    private static final int PLUGIN_ID = 90034;
    private static final String METADATA_PATH = "/latest/meta-data/";
    private static final List<String> METADATA_HOSTS =
            Arrays.asList(
                    "169.254.169.254", "aws.zaproxy.org", "100.100.100.200", "alibaba.zaproxy.org");

    private static final Logger LOGGER = LogManager.getLogger(CloudMetadataScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG);

    @Override
    public int getId() {
        return PLUGIN_ID;
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
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
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

    public AlertBuilder createAlert(HttpMessage newRequest, String host) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setAttack(host)
                .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "otherinfo"))
                .setMessage(newRequest);
    }

    @Override
    public void scan() {
        HttpMessage newRequest = getNewMsg();
        for (String host : METADATA_HOSTS) {
            try {
                newRequest.getRequestHeader().getURI().setPath(METADATA_PATH);
                newRequest.setUserObject(Collections.singletonMap("host", host));
                sendAndReceive(newRequest, false);
                if (isSuccess(newRequest) && newRequest.getResponseBody().length() > 0) {
                    this.createAlert(newRequest, host).raise();
                    return;
                }
            } catch (Exception e) {
                LOGGER.warn("Error sending URL {}", newRequest.getRequestHeader().getURI(), e);
            }
        }
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(createAlert(null, "www.example.com").build());
    }
}
