/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTagType;
import net.htmlparser.jericho.Tag;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class InformationDisclosureSuspiciousCommentsScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX =
            "pscanrules.informationdisclosuresuspiciouscomments.";
    private static final int PLUGIN_ID = 10027;

    public static final String suspiciousCommentsListDir = "xml";
    public static final String suspiciousCommentsListFile = "suspicious-comments.txt";
    private static final Logger logger =
            Logger.getLogger(InformationDisclosureSuspiciousCommentsScanRule.class);

    private static List<Pattern> patterns = null;

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        List<Pattern> patterns = getPatterns();
        int confidence = Alert.CONFIDENCE_MEDIUM;

        if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()) {
            StringBuilder todoComments = new StringBuilder();

            if (msg.getResponseHeader().isJavaScript()) {
                // Just treat as text
                String[] lines = msg.getResponseBody().toString().split("\n");
                for (String line : lines) {
                    for (Pattern pattern : patterns) {
                        if (pattern.matcher(line).find()) {
                            todoComments.append(
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "otherinfo", pattern, line));
                            todoComments.append("\n");
                            confidence = Alert.CONFIDENCE_LOW;
                            break; // Only need to record this line once
                        }
                    }
                }
            } else {
                // Can use the parser

                // Check the comments
                List<Tag> tags = source.getAllTags(StartTagType.COMMENT);
                for (Tag tag : tags) {
                    String tagStr = tag.toString();
                    for (Pattern pattern : patterns) {
                        if (pattern.matcher(tagStr).find()) {
                            todoComments.append(
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "otherinfo", pattern, tagStr));
                            todoComments.append("\n");
                            break; // Only need to record this comment once
                        }
                    }
                }
                // Check the scripts
                Element el;
                int offset = 0;
                while ((el = source.getNextElement(offset, HTMLElementName.SCRIPT)) != null) {
                    String elStr = el.toString();
                    for (Pattern pattern : patterns) {
                        if (pattern.matcher(elStr).find()) {
                            todoComments.append(
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "otherinfo", pattern, elStr));
                            todoComments.append("\n");
                            confidence = Alert.CONFIDENCE_LOW;
                            break; // Only need to record this script once
                        }
                    }
                    offset = el.getEnd();
                }
            }
            if (todoComments.length() > 0) {
                this.raiseAlert(msg, id, todoComments.toString(), confidence);
            }
        }
    }

    private void raiseAlert(HttpMessage msg, int id, String detail, int confidence) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(confidence)
                .setDescription(getDescription())
                .setOtherInfo(detail)
                .setSolution(getSolution())
                .setCweId(200) // CWE Id 200 - Information Exposure
                .setWascId(13) // WASC Id 13 - Info leakage
                .raise();
    }

    private static List<Pattern> getPatterns() {
        if (patterns == null) {
            patterns = new ArrayList<>();

            try {
                File f =
                        new File(
                                Constant.getZapHome()
                                        + File.separator
                                        + suspiciousCommentsListDir
                                        + File.separator
                                        + suspiciousCommentsListFile);
                if (!f.exists()) {
                    throw new IOException("Couldn't find resource: " + f.getAbsolutePath());
                }
                try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
                    String line = null;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.startsWith("#") && line.length() > 0) {
                            patterns.add(
                                    Pattern.compile(
                                            "\\b" + line + "\\b", Pattern.CASE_INSENSITIVE));
                        }
                    }
                }
            } catch (IOException e) {
                logger.error(
                        "Error on opening/reading suspicious comments file: "
                                + File.separator
                                + suspiciousCommentsListDir
                                + File.separator
                                + suspiciousCommentsListFile
                                + " Error: "
                                + e.getMessage());
            }
        }
        return patterns;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }
}
