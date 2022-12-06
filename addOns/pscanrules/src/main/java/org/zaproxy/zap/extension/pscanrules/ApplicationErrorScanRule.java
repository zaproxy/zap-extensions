/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.ContentMatcher;

/**
 * Plugin able to analyze the content for Application Error messages. The plugin find the first
 * occurrence of an exact match or a regex pattern matching according to an external file
 * definition. The vulnerability can be included inside the Information Leakage family (WASC-13)
 *
 * @author yhawke 2013
 */
public class ApplicationErrorScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.applicationerrors.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_ERRH_01_ERR,
                    CommonAlertTag.WSTG_V42_ERRH_02_STACK);

    private static final Logger LOGGER = LogManager.getLogger(ApplicationErrorScanRule.class);

    // Name of the file related to pattern's definition list
    private String APP_ERRORS_FILE =
            Constant.getZapHome()
                    + File.separator
                    + "xml"
                    + File.separator
                    + "application_errors.xml";

    public static final List<String> DEFAULT_ERRORS = Collections.emptyList();
    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER = () -> DEFAULT_ERRORS;
    public static final String ERRORS_PAYLOAD_CATEGORY = "Application-Errors";

    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    // Inner Content Matcher component with pattern definitions
    private ContentMatcher matcher = null;

    private ContentMatcher getContentMatcher() {
        if (matcher == null) {
            Path path = Paths.get(APP_ERRORS_FILE);
            try (InputStream is = Files.newInputStream(path)) {
                matcher = ContentMatcher.getInstance(is);
            } catch (IOException | IllegalArgumentException e) {
                LOGGER.warn(
                        "Unable to read {} input file: {}. Falling back to ZAP archive.",
                        getName(),
                        APP_ERRORS_FILE);
                matcher =
                        ContentMatcher.getInstance(
                                ApplicationErrorScanRule.class.getResourceAsStream(
                                        "/xml/application_errors.xml"));
            }
        }
        return matcher;
    }

    /**
     * Get this plugin id
     *
     * @return the ZAP id
     */
    @Override
    public int getPluginId() {
        return 90022;
    }

    /**
     * Get the plugin name
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    public String getReference() {
        return null;
    }

    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 200;
    }

    public int getWascId() {
        return 13;
    }

    /**
     * Perform the passive scanning of application errors inside the response content
     *
     * @param msg the message that need to be checked
     * @param id the id of the session
     * @param source the source code of the response
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        // First check if it's an INTERNAL SERVER ERROR
        if (getHelper().isPage500(msg)) {
            // We found it!
            // The AS raise an Internal Error
            // so a possible disclosure can be found
            if (AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
                // No need to alert
                return;
            }
            raiseAlert(msg, id, msg.getResponseHeader().getPrimeHeader(), Alert.RISK_LOW);

        } else if (!getHelper().isPage404(msg)
                && !msg.getResponseHeader().hasContentType("application/wasm")) {
            String body = msg.getResponseBody().toString();
            for (String payload : getCustomPayloads().get()) {
                if (body.contains(payload)) {
                    raiseAlert(msg, id, payload, getRisk());
                    return;
                }
            }
            String evidence = getContentMatcher().findInContent(body);
            if (evidence != null) {
                // We found it!
                // There exists a positive match of an
                // application error occurrence
                raiseAlert(msg, id, evidence, getRisk());
            }
        }
    }

    // Internal service method for alert management
    private void raiseAlert(HttpMessage msg, int id, String evidence, int risk) {
        buildAlert(msg, id, evidence, risk).raise();
    }

    private AlertBuilder buildAlert(HttpMessage msg, int id, String evidence, int risk) {
        return newAlert()
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId());
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        Alert example =
                buildAlert(null, 0, "ERROR: parser: parse error at or near", getRisk()).build();
        example.setTags(
                CommonAlertTag.mergeTags(example.getTags(), CommonAlertTag.CUSTOM_PAYLOADS));
        alerts.add(example);
        return alerts;
    }

    static Supplier<Iterable<String>> getCustomPayloads() {
        return payloadProvider;
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }
}
