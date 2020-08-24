/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/** Passive Scan Rule for Dangerous JS Functions https://github.com/zaproxy/zaproxy/issues/5673 */
public class JsFunctionScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.jsfunction.";

    public static final String FUNC_LIST_DIR = "txt";
    public static final String FUNC_LIST_FILE = "js-function-list.txt";
    private static final Logger LOGGER = Logger.getLogger(JsFunctionScanRule.class);
    private static final int PLUGIN_ID = 10110;

    public static final List<String> DEFAULT_FUNCTIONS = Collections.emptyList();
    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER =
            () -> DEFAULT_FUNCTIONS;
    public static final String JS_FUNCTION_PAYLOAD_CATEGORY = "JS-Function";

    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    private static List<Pattern> defaultPatterns = null;
    private static List<Pattern> patterns = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // This rule only scans responses received
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (msg.getResponseBody().length() <= 0
                || (!msg.getResponseHeader().isHtml() && !msg.getResponseHeader().isJavaScript())) {
            return;
        }
        if (defaultPatterns == null) {
            createDefaultPatterns();
        }
        loadPayload();
        StringBuilder evidence = new StringBuilder();
        if (msg.getResponseHeader().isHtml()) {
            // Check the scripts in HTML
            Element el;
            int offset = 0;
            while ((el = source.getNextElement(offset, HTMLElementName.SCRIPT)) != null) {
                String elStr = el.toString();
                searchPatterns(evidence, elStr);
                if (evidence.length() != 0) {
                    break;
                }
                offset = el.getEnd();
            }
        } else if (msg.getResponseHeader().isJavaScript()) {
            // Raw search on response body
            String content = msg.getResponseBody().toString();
            searchPatterns(evidence, content);
        }
        if (evidence.length() > 0) {
            this.raiseAlert(msg, id, evidence.toString());
        }
    }

    private void searchPatterns(StringBuilder evidence, String data) {
        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(data);
            if (matcher.find()) {
                evidence.append(matcher.group());
                break; // Only need to record one instance of vulnerability
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String evidence) {
        newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescription())
                .setSolution(getSolution())
                .setReference(getReference())
                .setEvidence(evidence)
                .setCweId(749) // CWE-749: Exposed Dangerous Method or Function
                .raise();
    }

    private static void createDefaultPatterns() {
        defaultPatterns = new ArrayList<>();
        try {
            File f =
                    new File(
                            Constant.getZapHome()
                                    + File.separator
                                    + FUNC_LIST_DIR
                                    + File.separator
                                    + FUNC_LIST_FILE);
            if (!f.exists()) {
                throw new IOException("Couldn't find resource: " + f.getAbsolutePath());
            }
            try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.startsWith("#") && line.length() > 0) {
                        addPattern(line, defaultPatterns);
                    }
                }
            }
        } catch (IOException e) {
            LOGGER.error(
                    "Error on opening/reading js functions file: "
                            + File.separator
                            + FUNC_LIST_DIR
                            + File.separator
                            + FUNC_LIST_FILE
                            + " Error: "
                            + e.getMessage());
        }
    }

    private static void loadPayload() {
        patterns = new ArrayList<>(defaultPatterns);
        for (String line : getJsFunctionPayloads().get()) {
            addPattern(line, patterns);
        }
    }

    private static void addPattern(String line, List<Pattern> list) {
        list.add(Pattern.compile(Pattern.quote(line), Pattern.CASE_INSENSITIVE));
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }

    private static Supplier<Iterable<String>> getJsFunctionPayloads() {
        return payloadProvider;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
