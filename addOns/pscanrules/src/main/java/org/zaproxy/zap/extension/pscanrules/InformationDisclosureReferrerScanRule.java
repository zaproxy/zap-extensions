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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PiiUtils;
import org.zaproxy.addon.commonlib.binlist.BinList;
import org.zaproxy.addon.commonlib.binlist.BinRecord;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class InformationDisclosureReferrerScanRule extends PluginPassiveScanner {

    protected static final String MESSAGE_PREFIX = "pscanrules.informationdisclosurereferrer.";
    private static final int PLUGIN_ID = 10025;

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED);

    public static final String URL_SENSITIVE_INFORMATION_DIR = "xml";
    public static final String URL_SENSITIVE_INFORMATION_FILE =
            "URL-information-disclosure-messages.txt";
    private static final Logger logger =
            LogManager.getLogger(InformationDisclosureReferrerScanRule.class);
    private List<String> messages = null;
    static Pattern emailAddressPattern =
            Pattern.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b");
    static Pattern creditCardPattern =
            Pattern.compile(
                    "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b");
    static Pattern usSSNPattern = Pattern.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b");

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        if (msg.getRequestHeader().getHeader(HttpHeader.REFERER) != null
                && !isRequestedURLSameDomainAsHTTPReferrer(
                        msg.getRequestHeader().getHostName(),
                        msg.getRequestHeader().getHeader(HttpHeader.REFERER))) {
            List<String> referrer = msg.getRequestHeader().getHeaderValues(HttpHeader.REFERER);
            String evidence;
            for (String referrerValue : referrer) {
                if ((evidence = doesURLContainsSensitiveInformation(referrerValue)) != null) {
                    this.raiseAlert(
                            msg,
                            evidence,
                            Constant.messages.getString(
                                    MESSAGE_PREFIX + "otherinfo.sensitiveinfo"));
                }
                if ((evidence = doesContainCreditCard(referrerValue)) != null) {
                    this.raiseCcAlert(
                            msg,
                            evidence,
                            Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.cc"),
                            BinList.getSingleton().get(evidence));
                }
                if ((evidence = doesContainEmailAddress(referrerValue)) != null) {
                    this.raiseAlert(
                            msg,
                            evidence,
                            Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.email"));
                }
                if ((evidence = doesContainUsSSN(referrerValue)) != null) {
                    this.raiseAlert(
                            msg,
                            evidence,
                            Constant.messages.getString(MESSAGE_PREFIX + "otherinfo.ssn"));
                }
            }
        }
    }

    private boolean isRequestedURLSameDomainAsHTTPReferrer(String host, String referrerURL) {
        boolean result = false;
        if (referrerURL.startsWith("/")) {
            result = true;
        } else {
            try {
                URI referrerURI = new URI(referrerURL, true);
                if (referrerURI.getHost() != null
                        && referrerURI.getHost().toLowerCase().equals(host.toLowerCase())) {
                    result = true;
                }
            } catch (URIException e) {
                logger.debug("Error: {}", e.getMessage());
            }
        }
        return result;
    }

    private void raiseAlert(HttpMessage msg, String evidence, String other) {
        newAlert()
                .setRisk(getRisk())
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setOtherInfo(other)
                .setSolution(getSolution())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId())
                .raise();
    }

    private void raiseCcAlert(HttpMessage msg, String evidence, String other, BinRecord binRec) {
        if (binRec != null) {
            other = other + '\n' + getBinRecString(binRec);
        }
        newAlert()
                .setRisk(getRisk())
                .setConfidence(binRec != null ? Alert.CONFIDENCE_HIGH : Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescription())
                .setOtherInfo(other)
                .setSolution(getSolution())
                .setEvidence(evidence)
                .setCweId(getCweId())
                .setWascId(getWascId())
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

    private List<String> loadFile(String file) {
        List<String> strings = new ArrayList<>();
        File f = new File(Constant.getZapHome() + File.separator + file);
        if (!f.exists()) {
            logger.error("No such file: {}", f.getAbsolutePath());
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
            logger.debug("Error on opening/reading debug error file. Error: {}", e.getMessage(), e);
        }

        return strings;
    }

    private String doesURLContainsSensitiveInformation(String url) {
        if (this.messages == null) {
            this.messages =
                    loadFile(
                            URL_SENSITIVE_INFORMATION_DIR
                                    + File.separator
                                    + URL_SENSITIVE_INFORMATION_FILE);
        }
        String lcUrl = url.toLowerCase();
        for (String msg : this.messages) {
            int start = lcUrl.indexOf(msg);
            if (start >= 0) {
                // Return the original (case exact) string so we can match it in the response
                return url.substring(start, start + msg.length());
            }
        }
        return null;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    public int getRisk() {
        return Alert.RISK_INFO;
    }

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

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    public int getCweId() {
        return 200; // CWE Id 200 - Information Exposure
    }

    public int getWascId() {
        return 13; // WASC Id - Info leakage
    }

    private String doesContainEmailAddress(String emailAddress) {
        Matcher matcher = emailAddressPattern.matcher(emailAddress);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    private String doesContainCreditCard(String creditCard) {
        Matcher matcher = creditCardPattern.matcher(creditCard);
        if (matcher.find()) {
            String candidate = matcher.group();
            if (PiiUtils.isValidLuhn(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private String doesContainUsSSN(String usSSN) {
        Matcher matcher = usSSNPattern.matcher(usSSN);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }
}
