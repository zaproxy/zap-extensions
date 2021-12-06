/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.Map;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * Active scan rule which checks whether or not POST requests with parameters are accepted as GET
 * equivalent requests.
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class GetForPostScanRule extends AbstractAppPlugin {

    private static final Logger LOG = LogManager.getLogger(GetForPostScanRule.class);
    private static final String MESSAGE_PREFIX = "ascanbeta.getforpost.";
    private static final int PLUGIN_ID = 10058;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS);

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
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return null;
    }

    @Override
    public void scan() {
        // Check if the user stopped things. One request per URL so check before
        // sending the request
        if (isStop()) {
            LOG.debug("Scan rule {} Stopping.", getName());
            return;
        }

        HttpMessage baseMsg = getBaseMsg();
        TreeSet<HtmlParameter> postParams = baseMsg.getFormParams();
        if (!baseMsg.getRequestHeader().getMethod().equalsIgnoreCase(HttpRequestHeader.POST)
                || postParams.isEmpty()) {
            return; // Not a POST or no form params, no reason to continue
        }

        HttpMessage newRequest = getNewMsg();
        newRequest.getRequestHeader().setMethod(HttpRequestHeader.GET);
        newRequest.setFormParams(new TreeSet<>());
        for (HtmlParameter param : postParams) {
            param.setType(HtmlParameter.Type.url);
        }
        newRequest.getRequestHeader().setGetParams(postParams);

        try {
            sendAndReceive(newRequest);
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while checking [{}] [{}] for {} Caught {} {}",
                    newRequest.getRequestHeader().getMethod(),
                    newRequest.getRequestHeader().getURI(),
                    getName(),
                    e.getClass().getName(),
                    e.getMessage());
            return;
        }

        if (newRequest.getResponseBody().equals(baseMsg.getResponseBody())) {
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setUri(baseMsg.getRequestHeader().getURI().toString())
                    .setEvidence(newRequest.getRequestHeader().getPrimeHeader())
                    .setMessage(newRequest)
                    .raise();
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 16; // Configuration
    }

    @Override
    public int getWascId() {
        return 20; // Improper Input Handling
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
