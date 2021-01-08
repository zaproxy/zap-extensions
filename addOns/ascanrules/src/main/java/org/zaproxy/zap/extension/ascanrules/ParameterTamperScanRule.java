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
// ZAP: 2012/03/15 Changed the method checkResult to use the class StringBuilder
// instead of StringBuffer.
// ZAP: 2012/04/25 Added @Override annotation to all appropriate methods.
// ZAP: 2012/12/28 Issue 447: Include the evidence in the attack field
// ZAP: 2013/01/25 Removed the "(non-Javadoc)" comments.
// ZAP: 2013/03/03 Issue 546: Remove all template Javadoc comments
// ZAP: 2016/02/02 Add isStop() checks
// ZAP: 2017/05/19 Correct data set in the raised alerts
// ZAP: 2019/05/08 Normalise format/indentation.
// ZAP: 2020/07/24 Normalise scan rule class names.
package org.zaproxy.zap.extension.ascanrules;

import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class ParameterTamperScanRule extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.parametertamper.";

    // private static final String[] PARAM_LIST = {"", "@", "+", "%A", "%1Z", "%", "%00", "|"};
    // problem sending "%A", "%1Z" to server - assume server can handle properly on this.
    // %0A not included as this is in CRLFInjection already.
    private static String[] PARAM_LIST = {
        "", "", "@", "+", AbstractPlugin.getURLDecode("%00"), "|"
    };

    private static Pattern patternErrorJava1 =
            Pattern.compile("javax\\.servlet\\.\\S+", PATTERN_PARAM);
    private static Pattern patternErrorJava2 =
            Pattern.compile("invoke.+exception|exception.+invoke", PATTERN_PARAM);
    private static Pattern patternErrorVBScript =
            Pattern.compile("Microsoft(\\s+|&nbsp)*VBScript(\\s+|&nbsp)+error", PATTERN_PARAM);
    private static Pattern patternErrorODBC1 =
            Pattern.compile("Microsoft OLE DB Provider for ODBC Drivers.*error", PATTERN_PARAM);
    private static Pattern patternErrorODBC2 =
            Pattern.compile("ODBC.*Drivers.*error", PATTERN_PARAM);
    private static Pattern patternErrorJet =
            Pattern.compile("Microsoft JET Database Engine.*error", PATTERN_PARAM);
    private static Pattern patternErrorPHP = Pattern.compile(" on line <b>", PATTERN_PARAM);
    private static Pattern patternErrorTomcat =
            Pattern.compile(
                    "(Apache Tomcat).*(Caused by:|HTTP Status 500 - Internal Server Error)",
                    PATTERN_PARAM);
    // ZAP: Added logger
    private static Logger log = LogManager.getLogger(ParameterTamperScanRule.class);

    @Override
    public int getId() {
        return 40008;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return "";
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        String attack = null;

        // always try normal query first
        HttpMessage normalMsg = getNewMsg();

        try {
            sendAndReceive(normalMsg);
        } catch (InvalidRedirectLocationException
                | SocketException
                | IllegalStateException
                | IllegalArgumentException
                | URIException
                | UnknownHostException ex) {
            log.debug(
                    "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                    ex.getClass().getName(),
                    ex.getMessage(),
                    normalMsg.getRequestHeader().getURI().toString());
            return; // Something went wrong, no point continuing
        } catch (Exception e) {
            // ZAP: Log exceptions
            log.warn(e.getMessage(), e);
            return;
        }

        if (!isPage200(normalMsg)) {
            return;
        }

        for (int i = 0; i < PARAM_LIST.length && !isStop(); i++) {
            HttpMessage testMsg = getNewMsg();
            if (i == 0) {
                // remove entire parameter when i=0;
                setParameter(testMsg, null, null);
                attack = null;
            } else {
                setParameter(testMsg, param, PARAM_LIST[i]);
                attack = PARAM_LIST[i];
            }
            try {
                try {
                    sendAndReceive(testMsg);
                } catch (InvalidRedirectLocationException
                        | SocketException
                        | IllegalStateException
                        | IllegalArgumentException
                        | URIException
                        | UnknownHostException ex) {
                    log.debug(
                            "Caught {} {} when accessing: {}.\n The target may have replied with a poorly formed redirect due to our input.",
                            ex.getClass().getName(),
                            ex.getMessage(),
                            testMsg.getRequestHeader().getURI().toString());
                    continue; // Something went wrong, move on to the next item in the PARAM_LIST
                }
                if (checkResult(testMsg, param, attack, normalMsg.getResponseBody().toString())) {
                    return;
                }
            } catch (Exception e) {
                // ZAP: Log exceptions
                log.warn(e.getMessage(), e);
            }
        }
    }

    private boolean checkResult(
            HttpMessage msg, String param, String attack, String normalHTTPResponse) {

        if (!isPage200(msg) && !isPage500(msg)) {
            return false;
        }

        // remove false positive if parameter have no effect on output
        if (msg.getResponseBody().toString().equals(normalHTTPResponse)) {
            return false;
        }

        StringBuilder sb = new StringBuilder();

        boolean issueFound = false;
        int confidence = Alert.CONFIDENCE_MEDIUM;
        if (matchBodyPattern(msg, patternErrorJava1, sb)
                && matchBodyPattern(msg, patternErrorJava2, null)) {
            issueFound = true;
        } else if (matchBodyPattern(msg, patternErrorVBScript, sb)
                || matchBodyPattern(msg, patternErrorODBC1, sb)
                || matchBodyPattern(msg, patternErrorODBC2, sb)
                || matchBodyPattern(msg, patternErrorJet, sb)
                || matchBodyPattern(msg, patternErrorTomcat, sb)
                || matchBodyPattern(msg, patternErrorPHP, sb)) {
            issueFound = true;
            confidence = Alert.CONFIDENCE_LOW;
        }

        if (issueFound) {
            newAlert()
                    .setConfidence(confidence)
                    .setParam(param)
                    .setAttack(attack)
                    .setEvidence(sb.toString())
                    .setMessage(msg)
                    .raise();
        }

        return issueFound;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 472;
    }

    @Override
    public int getWascId() {
        return 20;
    }
}
