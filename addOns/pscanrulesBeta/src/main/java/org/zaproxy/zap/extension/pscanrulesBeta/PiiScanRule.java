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
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.PiiUtils;
import org.zaproxy.addon.commonlib.binlist.BinList;
import org.zaproxy.addon.commonlib.binlist.BinRecord;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A scanner to passively scan for the presence of PII in response Currently only credit card
 * numbers
 *
 * @author Michael Kruglos (@michaelkruglos)
 */
public class PiiScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.pii.";

    private static final int PLUGIN_ID = 10062;

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

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {}

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String responseBody = msg.getResponseBody().toString();
        List<Candidate> candidates = getNumberSequences(responseBody);
        for (Candidate candidate : candidates) {
            for (CreditCard cc : CreditCard.values()) {
                Matcher matcher = cc.matcher(candidate.getCandidate());
                while (matcher.find()) {
                    String evidence = matcher.group();
                    if (PiiUtils.isValidLuhn(evidence) && !isSci(candidate.getContainingString())) {
                        BinRecord binRec = BinList.getSingleton().get(evidence);
                        raiseAlert(msg, evidence, cc.name, binRec);
                    }
                }
            }
        }
    }

    /**
     * Checks whether a particular {@code String} input appears to be a valid number in scientific
     * (exponent) notation. Ex: 2.14111111111111111e-2, 8.46786664623715E-47, 3.14111111111117293e5
     *
     * @param containingString the value to be checked.
     * @return {@code true} if the value successfully parses as a {@code Float}, {@code false}
     *     otherwise.
     */
    private static boolean isSci(String containingString) {
        if (!StringUtils.containsIgnoreCase(containingString, "e")) {
            return false;
        }

        // Maybe there's still something that isn't Float like, remove it
        containingString = containingString.replaceAll("[^0-9eE-]+", "");
        try {
            Float.parseFloat(containingString);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

    private void raiseAlert(HttpMessage msg, String evidence, String cardType, BinRecord binRec) {
        String other = Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", cardType);
        if (binRec != null) {
            other = other + '\n' + getBinRecString(binRec);
        }
        newAlert()
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(binRec != null ? Alert.CONFIDENCE_HIGH : Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(other)
                .setEvidence(evidence)
                .setCweId(359) // CWE-359: Exposure of Private Information ('Privacy Violation')
                .setWascId(13) // WASC-13: Information Leakage
                .raise();
    }

    private String getBinRecString(BinRecord binRec) {
        StringBuilder recString = new StringBuilder(75);
        recString
                .append(Constant.messages.getString(MESSAGE_PREFIX + "bin.field"))
                .append(' ')
                .append(binRec.getBin())
                .append('\n');
        recString
                .append(Constant.messages.getString(MESSAGE_PREFIX + "brand.field"))
                .append(' ')
                .append(binRec.getBrand())
                .append('\n');
        recString
                .append(Constant.messages.getString(MESSAGE_PREFIX + "category.field"))
                .append(' ')
                .append(binRec.getCategory())
                .append('\n');
        recString
                .append(Constant.messages.getString(MESSAGE_PREFIX + "issuer.field"))
                .append(' ')
                .append(binRec.getIssuer());
        return recString.toString();
    }

    private static List<Candidate> getNumberSequences(String inputString) {
        return getNumberSequences(inputString, 3);
    }

    private static List<Candidate> getNumberSequences(String inputString, int minSequence) {
        String regexString = String.format("(?:\\d{%d,}[\\s]*)+", minSequence);
        // Use RE2/J to avoid StackOverflowError when the response has many numbers.
        com.google.re2j.Matcher matcher =
                com.google.re2j.Pattern.compile(regexString).matcher(inputString);
        List<Candidate> result = new ArrayList<>();
        while (matcher.find()) {
            int proposedEnd = matcher.end() + 3;
            result.add(
                    new Candidate(
                            matcher.group().replaceAll("\\s+", ""),
                            inputString
                                    .substring(
                                            matcher.start(),
                                            inputString.length() > proposedEnd
                                                    ? matcher.end() + 3
                                                    : inputString.length())
                                    .replaceAll("\\s+", "")));
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

    private static class Candidate {
        private final String candidate;
        private final String containingString;

        Candidate(String candidate, String containingString) {
            this.candidate = candidate;
            this.containingString = containingString;
        }

        public String getCandidate() {
            return candidate;
        }

        public String getContainingString() {
            return containingString;
        }
    }
}
