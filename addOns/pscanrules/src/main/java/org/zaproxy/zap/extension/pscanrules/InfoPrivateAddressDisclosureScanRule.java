/*
 *
 * Paros and its related class files.
 *
 * Paros is an HTTP/HTTPS proxy for assessing web application security.
 * Copyright (C) 2003-2004 Chinotec Technologies Company
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the Clarified Artistic License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Clarified Artistic License for more details.
 *
 * You should have received a copy of the Clarified Artistic License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
// ZAP: 2012/01/02 Separate param and attack
// ZAP: 2012/03/15 Changed the method scan to use the class StringBuilder
// instead of String.
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field, and made into a passive scan
// rule
// ZAP: 2016/10/26 Issue 2834: Fixed the regex
// ZAP: 2016/12/15 Issue 3031: Ignore requested private IP addresses on Private IP Disclosure scan
// ZAP: 2017/06/06 Issue 3549: Exclude port when comparing hosts
// ZAP: 2019/05/08 Normalise format/indentation.
// ZAP: 2020/06/22 Normalise scan rule class naming and i18n keys.
// ZAP: 2021/08/12 Fix handling of octets with leading zeros
// ZAP: 2021/08/12 Issue 6749: Fix handling of non-octets

package org.zaproxy.zap.extension.pscanrules;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Checks content for private IP V4 addresses as well as Amazon EC2 private hostnames (for example,
 * ip-10-34-56-78).
 */
public class InfoPrivateAddressDisclosureScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.infoprivateaddressdisclosure.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A01_BROKEN_AC,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED);

    private static final String REGULAR_IP_OCTET = "(25[0-5]|2[0-4]\\d|[01]?\\d{1,2})";

    private static final String NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER = "\\b(?!\\.\\d)";

    private static final String NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER = "\\b(?!-\\d)";

    private static final String NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER = "(?<!\\d\\.)\\b";

    private static final String PRECEDED_BY_IP_DASH = "\\bip-";

    /** Pattern for private IP V4 addresses as well as Amazon EC2 private hostnames */
    public static final Pattern patternPrivateIP =
            Pattern.compile(
                    "("
                            + NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER
                            + "10\\.("
                            + REGULAR_IP_OCTET
                            + "\\.){2}"
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER
                            + "|"
                            + NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER
                            + "172\\."
                            + "(3[01]|2\\d|1[6-9])\\."
                            + REGULAR_IP_OCTET
                            + "\\."
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER
                            + "|"
                            + NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER
                            + "192\\.168\\."
                            + REGULAR_IP_OCTET
                            + "\\."
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER
                            + "|"
                            // find IPs from AWS hostnames such as "ip-10-2-3-200"
                            + PRECEDED_BY_IP_DASH
                            + "10-("
                            + REGULAR_IP_OCTET
                            + "-){2}"
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER
                            + "|"
                            + PRECEDED_BY_IP_DASH
                            + "172-"
                            + "(3[01]|2\\d|1[6-9])-"
                            + REGULAR_IP_OCTET
                            + "-"
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER
                            + "|"
                            + PRECEDED_BY_IP_DASH
                            + "192-168-"
                            + REGULAR_IP_OCTET
                            + "-"
                            + REGULAR_IP_OCTET
                            + NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER
                            + ")"
                            // find regular ports (0-65535)
                            + "(:(0|[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65([0-4]\\d{2}|5[0-2]\\d|53[0-5]))\\b)?",
                    Pattern.MULTILINE);

    @Override
    public int getPluginId() {
        return 00002;
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

    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
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

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String host = msg.getRequestHeader().getHostName();

        String txtBody = msg.getResponseBody().toString();
        Matcher matcher = patternPrivateIP.matcher(txtBody);
        StringBuilder sbTxtFound = new StringBuilder();
        String firstOne = null;

        while (matcher.find()) {
            if (getAlertThreshold() != AlertThreshold.LOW
                    && matcher.group(1).equalsIgnoreCase(host)) {
                continue;
            }

            if (firstOne == null) {
                firstOne = matcher.group();
            }
            sbTxtFound.append(matcher.group()).append("\n");
        }

        if (sbTxtFound.length() != 0) {
            newAlert()
                    .setRisk(getRisk())
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setDescription(getDescription())
                    .setOtherInfo(sbTxtFound.toString())
                    .setSolution(getSolution())
                    .setReference(getReference())
                    .setEvidence(firstOne)
                    .setCweId(getCweId())
                    .setWascId(getWascId())
                    .raise();
        }
    }

    public int getRisk() {
        return Alert.RISK_LOW;
    }
}
