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
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class InformationDisclosureInUrlScanRule extends PluginPassiveScanner {

    public static final String MESSAGE_PREFIX = "pscanrules.informationdisclosureinurl.";
    private static final int PLUGIN_ID = 10024;

    public static final String URL_SENSITIVE_INFORMATION_DIR = "xml";
    public static final String URL_SENSITIVE_INFORMATION_FILE =
            "URL-information-disclosure-messages.txt";
    private static final Logger logger = Logger.getLogger(InformationDisclosureInUrlScanRule.class);
    private static List<String> messages = null;
    static Pattern emailAddressPattern =
            Pattern.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b");
    // CC Pattern Source:
    // https://www.oreilly.com/library/view/regular-expressions-cookbook/9781449327453/ch04s20.html
    static Pattern creditCardPattern =
            Pattern.compile(
                    "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b");
    static Pattern usSSNPattern = Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b");

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        TreeSet<HtmlParameter> urlParams = msg.getUrlParams();
        for (HtmlParameter urlParam : urlParams) {
            String match = doesParamNameContainsSensitiveInformation(urlParam.getName());
            if (match != null) {
                this.raiseAlert(
                        msg,
                        id,
                        urlParam.getName(),
                        urlParam.getName(),
                        Constant.messages.getString(
                                MESSAGE_PREFIX + "otherinfo.sensitiveinfo",
                                match,
                                urlParam.getName()));
            }
            if (isCreditCard(urlParam.getValue())) {
                this.raiseAlert(
                        msg,
                        id,
                        urlParam.getName(),
                        urlParam.getValue(),
                        Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.cc"));
            }
            if (isEmailAddress(urlParam.getValue())) {
                this.raiseAlert(
                        msg,
                        id,
                        urlParam.getName(),
                        urlParam.getValue(),
                        Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.email"));
            }
            if (isUsSSN(urlParam.getValue())) {
                this.raiseAlert(
                        msg,
                        id,
                        urlParam.getName(),
                        urlParam.getValue(),
                        Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.ssn"));
            }
        }
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {}

    private void raiseAlert(HttpMessage msg, int id, String param, String evidence, String other) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setParam(param)
                .setOtherInfo(other)
                .setSolution(getSolution())
                .setEvidence(evidence)
                .setCweId(200) // CWE Id 200 - Information Exposure
                .setWascId(13) // WASC Id 13 - Info leakage
                .raise();
    }

    private static List<String> loadFile(String file) {
        List<String> strings = new ArrayList<String>();
        File f = new File(Constant.getZapHome() + File.separator + file);
        if (!f.exists()) {
            logger.error("No such file: " + f.getAbsolutePath());
            return strings;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("#")) {
                    strings.add(line.trim().toLowerCase());
                }
            }
        } catch (IOException e) {
            logger.debug("Error on opening/reading debug error file. Error: " + e.getMessage(), e);
        }

        return strings;
    }

    private static String doesParamNameContainsSensitiveInformation(String paramName) {
        if (messages == null) {
            messages =
                    loadFile(
                            URL_SENSITIVE_INFORMATION_DIR
                                    + File.separator
                                    + URL_SENSITIVE_INFORMATION_FILE);
        }
        String ciParamName = paramName.toLowerCase();
        for (String msg : messages) {
            if (ciParamName.contains(msg)) {
                return msg;
            }
        }
        return null;
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

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    private boolean isEmailAddress(String emailAddress) {
        Matcher matcher = emailAddressPattern.matcher(emailAddress);
        return matcher.find();
    }

    private boolean isCreditCard(String creditCard) {
        Matcher matcher = creditCardPattern.matcher(creditCard);
        return matcher.find();
    }

    private boolean isUsSSN(String usSSN) {
        Matcher matcher = usSSNPattern.matcher(usSSN);
        return matcher.find();
    }
}
