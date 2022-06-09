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
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
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
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

/**
 * An active scan rule to test for Spring Actuators revealing too much info. Health might be the
 * most commonly enabled but if health is enabled, so might be Thread Dump or Heap Dump which could
 * be serious https://docs.spring.io/spring-boot/docs/current/actuator-api/htmlsingle/#overview
 *
 * @author sgerlach
 */
public class SpringActuatorScanRule extends AbstractHostPlugin {

    private static final String MESSAGE_PREFIX = "ascanalpha.springactuator.";
    private static final int PLUGIN_ID = 40042;
    private static final Logger LOG = LogManager.getLogger(SpringActuatorScanRule.class);
    private static final Pattern CONTENT_TYPE =
            Pattern.compile(
                    "application\\/vnd\\.spring-boot\\.actuator\\.v[0-9]\\+json|application\\/json",
                    Pattern.MULTILINE);
    private static final Pattern JSON_PAYLOAD = Pattern.compile("\\{.*\\:.*\\}", Pattern.MULTILINE);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A05_BROKEN_AC,
                    CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE);

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.SPRING);
    }

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
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getWascId() {
        return 13;
    }

    @Override
    public int getCweId() {
        return 215;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private String getAlertName() {
        return getName();
    }

    @Override
    public void scan() {
        String[] endpointList = {"actuator/health"};
        String[] encodingTypes = {null, "application/json"};
        for (String endpoint : endpointList) {
            for (String encodingType : encodingTypes) {
                if (isStop()) {
                    LOG.debug("Scan rule {} stopping.", getName());
                    return;
                }
                HttpMessage testMsg = sendActuatorRequest(encodingType, endpoint);
                if (testMsg == null) {
                    continue;
                }
                String contentType = testMsg.getResponseHeader().getNormalisedContentTypeValue();
                if (contentType != null && isPage200(testMsg)) {
                    String responseBody = testMsg.getResponseBody().toString();
                    boolean matches =
                            CONTENT_TYPE.matcher(contentType).find()
                                    && JSON_PAYLOAD.matcher(responseBody).find();
                    if (matches) {
                        raiseAlert(testMsg, Alert.CONFIDENCE_MEDIUM, getRisk());
                        break;
                    }
                }
            }
        }
    }

    private static String generatePath(String baseUriPath, String actuatorEndpoint) {
        String newPath = "";
        if (baseUriPath.contains("/")) {
            if (baseUriPath.endsWith("/")) {
                newPath = baseUriPath + actuatorEndpoint;
            } else {
                newPath =
                        baseUriPath.substring(0, baseUriPath.lastIndexOf('/'))
                                + "/"
                                + actuatorEndpoint;
            }
        } else {
            newPath = baseUriPath + "/" + actuatorEndpoint;
        }
        return newPath;
    }

    private HttpMessage sendActuatorRequest(String encodingType, String actuatorEndpoint) {
        HttpMessage testMsg = getNewMsg();
        try {
            URI baseUri = getBaseMsg().getRequestHeader().getURI();
            String baseUriPath = baseUri.getPath() == null ? "" : baseUri.getPath();
            URI testUri =
                    new URI(
                            baseUri.getScheme(),
                            null,
                            baseUri.getHost(),
                            baseUri.getPort(),
                            generatePath(baseUriPath, actuatorEndpoint));
            testMsg.getRequestHeader().setURI(testUri);
            testMsg.getRequestHeader().setMethod(HttpRequestHeader.GET);
            testMsg.getRequestHeader()
                    .setHeader(HttpHeader.ACCEPT_ENCODING, encodingType); // Set this correctly
            testMsg.setRequestBody("");
            sendAndReceive(testMsg);
            return testMsg;
        } catch (IOException e) {
            LOG.warn(
                    "An error occurred while checking [{}] [{}] for {} Caught {} {}",
                    testMsg.getRequestHeader().getMethod(),
                    testMsg.getRequestHeader().getURI(),
                    getName(),
                    e.getClass().getName(),
                    e.getMessage());
        }
        return null;
    }

    private void raiseAlert(HttpMessage msg, int confidence, int risk) {
        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setName(getAlertName())
                .setEvidence(msg.getResponseHeader().getPrimeHeader())
                .setReference(getReference())
                .setMessage(msg)
                .setEvidence(StringUtils.left(msg.getResponseBody().toString(), 100))
                .raise();
    }
}
