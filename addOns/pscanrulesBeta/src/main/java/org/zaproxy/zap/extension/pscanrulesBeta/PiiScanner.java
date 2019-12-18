/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A scanner to passively scan for the presence of PII in response Currently only credit card
 * numbers
 *
 * @author Michael Kruglos (@michaelkruglos) TODO Extract credit card code when moved to beta(?) to
 *     also be used by InformationDisclosureReferrerScanner
 */
public class PiiScanner extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.piiscanner.";

    private static final int PLUGIN_ID = 10062;

    private PassiveScanThread parent = null;

    private enum CreditCard {
        AMERICAN_EXPRESS("American Express", "\\b(?:3[47][0-9]{13})\\b"),
        DINERSCLUB("DinersClub", "\\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\\b"),
        DISCOVER("Discover", "\\b(?:6(?:011|5[0-9]{2})(?:[0-9]{12}))\\b"),
        JCB("Jcb", "\\b(?:(?:2131|1800|35\\d{3})\\d{11})\\b"),
        MAESTRO("Maestro", "\\b(?:(?:5[0678]\\d\\d|6304|6390|67\\d\\d)\\d{8,15})\\b"),
        MASTERCARD(
                "Mastercard",
                "\\b(?:(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})\\b"),
        VISA("Visa", "\\b(?:4[0-9]{12})(?:[0-9]{3})?\\b");

        private final String name;
        private final Pattern pattern;

        CreditCard(String name, String regex) {
            this.name = name;
            this.pattern = Pattern.compile(regex);
        }

        public Matcher matcher(String cc) {
            return pattern.matcher(cc);
        }

        @Override
        public String toString() {
            return name;
        }
    }

    public PiiScanner() {}

    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String responseBody = msg.getResponseBody().toString();
        List<String> candidates = getNumberSequences(responseBody);
        for (String candidate : candidates) {
            for (CreditCard cc : CreditCard.values()) {
                Matcher matcher = cc.matcher(candidate);
                while (matcher.find()) {
                    String evidence = matcher.group();
                    if (validateLuhnChecksum(evidence)) {
                        raiseAlert(msg, id, evidence, cc.name);
                    }
                }
            }
        }
    }

    private static boolean validateLuhnChecksum(String evidence) {
        int sum = 0;
        int parity = evidence.length() % 2;
        for (int index = 0; index < evidence.length(); index++) {
            int digit = Integer.parseInt(evidence.substring(index, index + 1));
            if ((index % 2) == parity) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
        }
        return (sum % 10) == 0;
    }

    private void raiseAlert(HttpMessage msg, int id, String evidence, String cardType) {
        Alert alert = new Alert(getPluginId(), Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, getName());
        alert.setDetail(
                Constant.messages.getString(MESSAGE_PREFIX + "desc"),
                msg.getRequestHeader().getURI().toString(),
                "", // parameter
                "", // attack
                Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", cardType),
                "", // solution
                "",
                evidence, // evidence, if any
                359, // CWE-359: Exposure of Private Information ('Privacy Violation')
                13, // WASC-13: Information Leakage
                msg);

        parent.raiseAlert(id, alert);
    }

    private static List<String> getNumberSequences(String inputString) {
        return getNumberSequences(inputString, 3);
    }

    private static List<String> getNumberSequences(String inputString, int minSequence) {
        String regexString = String.format("(?:\\d{%d,}[\\s]*)+", minSequence);
        // Use RE2/J to avoid StackOverflowError when the response has many numbers.
        com.google.re2j.Matcher matcher =
                com.google.re2j.Pattern.compile(regexString).matcher(inputString);
        List<String> result = new ArrayList<>();
        while (matcher.find()) {
            result.add(matcher.group().replaceAll("\\s+", ""));
        }
        return result;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }
}
