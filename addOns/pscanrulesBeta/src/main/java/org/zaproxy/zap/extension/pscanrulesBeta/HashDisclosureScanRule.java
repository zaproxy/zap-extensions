/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A class to passively scan responses known Hash signatures
 *
 * @author 70pointer@gmail.com
 */
public class HashDisclosureScanRule extends PluginPassiveScanner {

    /** a map of a regular expression pattern to details of the Hash type found */
    static Map<Pattern, HashAlert> hashPatterns = new LinkedHashMap<Pattern, HashAlert>();

    static {
        // Traditional DES: causes *way* too many false positives to enable this..
        // Example: sa3tHJ3/KuYvI
        // hashPatterns.put(Pattern.compile("\\b[A-Za-z0-9/]{13}\\b", Pattern.CASE_INSENSITIVE), new
        // HashAlert ("Traditional DES", Alert.RISK_HIGH, Alert.WARNING));

        hashPatterns.put(
                Pattern.compile("\\$LM\\$[a-f0-9]{16}", Pattern.CASE_INSENSITIVE),
                new HashAlert("LanMan / DES", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$K4\\$[a-f0-9]{16},", Pattern.CASE_INSENSITIVE),
                new HashAlert("Kerberos AFS DES", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$2a\\$05\\$[a-zA-z0-9\\+\\-_./=]{53}", Pattern.CASE_INSENSITIVE),
                new HashAlert("OpenBSD Blowfish", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$2y\\$05\\$[a-zA-z0-9\\+\\-_./=]{53}", Pattern.CASE_INSENSITIVE),
                new HashAlert("OpenBSD Blowfish", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // MD5 Crypt
        // Example: $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/
        hashPatterns.put(
                Pattern.compile("\\$1\\$[./0-9A-Za-z]{0,8}\\$[./0-9A-Za-z]{22}"),
                new HashAlert("MD5 Crypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // SHA-256 Crypt
        // Example: $5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5
        // Example: $5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6
        hashPatterns.put(
                Pattern.compile("\\$5\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{43}"),
                new HashAlert("SHA-256 Crypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$5\\$rounds=[0-9]+\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{43}"),
                new HashAlert("SHA-256 Crypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // SHA-512 Crypt
        // Example:
        // $6$zWwwXKNj$gLAOoZCjcr8p/.VgV/FkGC3NX7BsXys3KHYePfuIGMNjY83dVxugPYlxVg/evpcVEJLT/rSwZcDMlVVf/bhf.1
        // Example:
        // $6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21
        hashPatterns.put(
                Pattern.compile("\\$6\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{86}"),
                new HashAlert("SHA-512 Crypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$6\\$rounds=[0-9]+\\$[./0-9A-Za-z]{0,16}\\$[./0-9A-Za-z]{86}"),
                new HashAlert("SHA-512 Crypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // BCrypt
        // Example: $2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe
        hashPatterns.put(
                Pattern.compile("\\$2\\$[0-9]{2}\\$[./0-9A-Za-z]{53}"),
                new HashAlert("BCrypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$2a\\$[0-9]{2}\\$[./0-9A-Za-z]{53}"),
                new HashAlert("BCrypt", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // NTLM
        // Example: $NT$7f8fe03093cc84b267b109625f6bbf4b
        hashPatterns.put(
                Pattern.compile("\\$3\\$\\$[0-9a-f]{32}"),
                new HashAlert("NTLM", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));
        hashPatterns.put(
                Pattern.compile("\\$NT\\$[0-9a-f]{32}"),
                new HashAlert("NTLM", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH));

        // Mac OS X salted SHA-1
        // Example: 0E6A48F765D0FFFFF6247FA80D748E615F91DD0C7431E4D9
        hashPatterns.put(
                Pattern.compile("\\b[0-9A-F]{48}\\b"),
                new HashAlert("Mac OSX salted SHA-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM));

        // SHA hashes occur fairly frequently in various legitimate uses, and are not necessarily
        // indicative of an issue.
        hashPatterns.put(
                Pattern.compile("\\b[0-9a-f]{128}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("SHA-512", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));
        hashPatterns.put(
                Pattern.compile("\\b[0-9a-f]{96}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("SHA-384", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));
        hashPatterns.put(
                Pattern.compile("\\b[0-9a-f]{64}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("SHA-256", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));
        hashPatterns.put(
                Pattern.compile("\\b[0-9a-f]{56}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("SHA-224", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));
        hashPatterns.put(
                Pattern.compile("\\b[0-9a-f]{40}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("SHA-1", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));

        // LanMan (clashes with MD4/MD5) - note the case sensitivity here, however
        // Example: 855c3697d9979e78ac404c4ba2c66533)
        hashPatterns.put(
                Pattern.compile("\\b\\[0-9a-f]{32}\\b"),
                new HashAlert("LanMan", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));

        // MD4/5 (clashes with LanMan)
        // MD4/5 hashes occur fairly frequently in various legitimate uses, and are not necessarily
        // indicative of an issue.
        hashPatterns.put(
                Pattern.compile("(?<!jsessionid=)\\b[0-9a-f]{32}\\b", Pattern.CASE_INSENSITIVE),
                new HashAlert("MD4 / MD5", Alert.RISK_LOW, Alert.CONFIDENCE_LOW));

        // TODO: for the main hash types, verify the value by hashing the parameters
        //  - if the hash value can be re-generated, then it is a "reflection" attack
        //  - if the hash value cannot be re-generated using the available data, then perhaps it is
        // being retrieved from a database??? => Dangerous.
    }

    private static Logger log = Logger.getLogger(HashDisclosureScanRule.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.hashdisclosure.";

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    /**
     * scans the HTTP request for Hash signatures
     *
     * @param msg
     * @param id
     */
    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {

        if (log.isDebugEnabled()) log.debug("Checking request of message " + msg + " for Hashes");

        // get the request contents as an array of Strings, so we can match against them
        String requestheader = msg.getRequestHeader().getHeadersAsString();
        String requestbody = msg.getRequestBody().toString();
        String[] requestparts = {requestheader, requestbody};

        checkForHashes(msg, id, requestparts);
    }

    /**
     * scans the HTTP response for Hash signatures
     *
     * @param msg
     * @param id
     * @param source unused
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        if (log.isDebugEnabled()) log.debug("Checking response of message " + msg + " for Hashes");

        // get the response contents as an array of Strings, so we can match against them
        String responseheader = msg.getResponseHeader().getHeadersAsString();
        String responsebody = msg.getResponseBody().toString();
        String[] responseparts = {responseheader, responsebody};

        checkForHashes(msg, id, responseparts);
    }

    /**
     * checks for hashes in the given array of strings, which relate to the parameter message
     *
     * @param msg
     * @param id
     * @param haystacks
     */
    public void checkForHashes(HttpMessage msg, int id, String[] haystacks) {
        // try each of the patterns in turn against the response.
        String hashType = null;
        Iterator<Pattern> patternIterator = hashPatterns.keySet().iterator();

        int minimumConfidence = Alert.CONFIDENCE_LOW;
        switch (this.getAlertThreshold()) {
            case HIGH:
                minimumConfidence = Alert.CONFIDENCE_HIGH;
                break;
            case MEDIUM:
                minimumConfidence = Alert.CONFIDENCE_MEDIUM;
                break;
        }

        while (patternIterator.hasNext()) {
            Pattern hashPattern = patternIterator.next();
            HashAlert hashalert = hashPatterns.get(hashPattern);
            if (hashalert.getConfidence() < minimumConfidence) {
                continue;
            }
            hashType = hashalert.getDescription();
            if (log.isDebugEnabled())
                log.debug("Trying Hash Pattern: " + hashPattern + " for hash type " + hashType);
            for (String haystack : haystacks) {
                Matcher matcher = hashPattern.matcher(haystack);
                while (matcher.find()) {
                    String evidence = matcher.group();
                    if (log.isDebugEnabled())
                        log.debug("Found a match for hash type " + hashType + ":" + evidence);
                    if (evidence != null && evidence.length() > 0) {
                        // we found something
                        newAlert()
                                .setName(getName() + " - " + hashType)
                                .setRisk(hashalert.getRisk())
                                .setConfidence(hashalert.getConfidence())
                                .setDescription(getDescription() + " - " + hashType)
                                .setOtherInfo(getExtraInfo(msg, evidence))
                                .setSolution(getSolution())
                                .setReference(getReference())
                                .setEvidence(evidence)
                                .setCweId(200) // Information Exposure,
                                .setWascId(13) // Information Leakage
                                .raise();
                        // do NOT break at this point.. we need to find *all* the potential hashes
                        // in the response..
                    }
                }
            }
        }
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public int getPluginId() {
        return 10097;
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

    private String getExtraInfo(HttpMessage msg, String arg0) {
        return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo", arg0);
    }

    static class HashAlert {
        private String description;
        private int risk;
        private int confidence;

        public String getDescription() {
            return description;
        }

        public int getRisk() {
            return risk;
        }

        public int getConfidence() {
            return confidence;
        }

        public HashAlert(String description, int risk, int confidence) {
            this.description = description;
            this.risk = risk;
            this.confidence = confidence;
        }
    }
}
