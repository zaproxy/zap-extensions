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
package org.zaproxy.zap.extension.pscanrules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Checks content for private IP V4 addresses as well as Amazon EC2 private hostnames (for example,
 * ip-10-34-56-78).
 */
public class InfoPrivateAddressDisclosureScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.infoprivateaddressdisclosure.";

    private static final String REGULAR_IP_OCTET = "(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})";

    /** Pattern for private IP V4 addresses as well as Amazon EC2 private hostnames */
    public static final Pattern patternPrivateIP =
            Pattern.compile(
                    "("
                            + "\\b10\\.("
                            + REGULAR_IP_OCTET
                            + "\\.){2}"
                            + REGULAR_IP_OCTET
                            + "\\b|"
                            + "\\b172\\."
                            + "(3[01]|2[0-9]|1[6-9])\\."
                            + REGULAR_IP_OCTET
                            + "\\."
                            + REGULAR_IP_OCTET
                            + "\\b|"
                            + "\\b192\\.168\\."
                            + REGULAR_IP_OCTET
                            + "\\."
                            + REGULAR_IP_OCTET
                            + "\\b|"
                            // find IPs from AWS hostnames such as "ip-10-2-3-200"
                            + "\\bip-10-("
                            + REGULAR_IP_OCTET
                            + "-){2}"
                            + REGULAR_IP_OCTET
                            + "\\b|"
                            + "\\bip-172-"
                            + "(3[01]|2[0-9]|1[6-9])-"
                            + REGULAR_IP_OCTET
                            + "-"
                            + REGULAR_IP_OCTET
                            + "\\b|"
                            + "\\bip-192-168-"
                            + REGULAR_IP_OCTET
                            + "-"
                            + REGULAR_IP_OCTET
                            + "\\b"
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
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Ignore
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
                    .setCweId(200)
                    .setWascId(13)
                    .raise();
        }
    }

    private int getRisk() {
        return Alert.RISK_LOW;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }
}
