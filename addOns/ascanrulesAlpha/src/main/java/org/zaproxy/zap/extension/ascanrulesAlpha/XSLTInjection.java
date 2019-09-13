/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Active scan rule which checks for signs of XSLT injection vulnerabilities with requests
 *
 * @author CaptainFreak
 * @author ZainabAlShowely
 */
public class XSLTInjection extends AbstractAppParamPlugin {
    private static final String MESSAGE_PREFIX = "ascanalpha.xsltinjection.";

    private static String[] errorCausingPayloads = {"<"};

    private static String[] evidenceError = {
        "compilation error", "XSLT compile error", "SAXParseException"
    };

    private static String[] vendorReturningPayloads = {
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/>",
        "system-property(\'xsl:vendor\')/>",
        "\"/><xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--",
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--"
    };

    private static String[] evidenceVendors = {
        "libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"
    };

    private static String[] evidencePortScanning = {
        "failed to open stream",
        "Invalid Http response",
        "Connection Refused",
        "No connection could be made because the target machine actively refused it",
        "Can not load requested doc"
    };

    private static String[] cmdExecPayloads = {
        "<xsl:variable name=\"rtobject\" select=\"runtime:getRuntime()\"/>\n"
                + "<xsl:variable name=\"process\" select=\"runtime:exec($rtobject,'erroneous_command')\"/>\n"
                + "<xsl:variable name=\"waiting\" select=\"process:waitFor($process)\"/>\n"
                + "<xsl:value-of select=\"$process\"/>",
        "<xsl:value-of select=\"php:function('exec','erroneous_command 2>&amp;1')\"/>"
    };

    private static String[] evidenceCmdExec = {
        "Cannot run program", "erroneous_command: not found",
    };

    // Creates XSLTInjectionCheck objects to avoid having to pass
    // the payloads, responses and resources strings afterwards
    private XSLTInjectionCheck ERROR_CHECK =
            new XSLTInjectionCheck(errorCausingPayloads, evidenceError, "error");
    private XSLTInjectionCheck VENDOR_CHECK =
            new XSLTInjectionCheck(vendorReturningPayloads, evidenceVendors, "vendor");
    private XSLTInjectionCheck PORTSCAN_CHECK =
            new XSLTInjectionCheck(
                    new String[] {getXslForPortScan()}, evidencePortScanning, "portscan");
    private XSLTInjectionCheck COMMAND_EXEC_CHECK =
            new XSLTInjectionCheck(cmdExecPayloads, evidenceCmdExec, "command");

    private static final Logger LOG = Logger.getLogger(XSLTInjection.class);

    // used to check against the attack strength
    private int requestsSent = 0;
    // map setting the limits associated with each attack strength
    private static Map<AttackStrength, Integer> strengthToRequestCountMap = new HashMap<>();

    static {
        strengthToRequestCountMap.put(AttackStrength.DEFAULT, 12);
        strengthToRequestCountMap.put(AttackStrength.LOW, 6);
        strengthToRequestCountMap.put(AttackStrength.MEDIUM, 12);
        strengthToRequestCountMap.put(AttackStrength.HIGH, 24);
        strengthToRequestCountMap.put(AttackStrength.INSANE, 500);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // initial check verifies if injecting certain strings causes XSLT related
        // errors
        if (tryInjection(msg, param, ERROR_CHECK)) {
            // verifies if we can get the vendor of the processor
            tryInjection(msg, param, VENDOR_CHECK);

            // verifies if we can get a response relating to portscan
            tryInjection(msg, param, PORTSCAN_CHECK);
        }
    }

    private Boolean tryInjection(HttpMessage msg, String param, XSLTInjectionCheck checkType) {
        for (String payload : checkType.payloads) {
            try {
                if (isStop() || requestsLimitReached()) { // stop before sending request
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Scanner " + getName() + " Stopping.");
                    }
                    return false;
                }
                msg = sendRequest(msg, param, payload);

                for (String response : checkType.responses) {
                    if (getBaseMsg().getResponseBody().toString().contains(response)) {
                        continue; // skip as the original contains the suspicious response
                    }

                    if (msg.getResponseBody().toString().contains(response)) {
                        // found a possible injection
                        raiseAlert(msg, param, payload, response, checkType);
                        return true;
                    }
                }
            } catch (Exception e) {
                LOG.warn(
                        "An error occurred while checking ["
                                + msg.getRequestHeader().getMethod()
                                + "] ["
                                + msg.getRequestHeader().getURI()
                                + "] for "
                                + getName()
                                + " Caught "
                                + e.getClass().getName()
                                + " "
                                + e.getMessage());
                continue;
            }
        }
        return false;
    }

    private HttpMessage sendRequest(HttpMessage msg, String param, String value)
            throws IOException {
        msg = getNewMsg();
        setParameter(msg, param, value);
        sendAndReceive(msg);
        requestsSent++;
        return msg;
    }

    private String getXslForPortScan() {
        // only tests one port for now
        try {
            return String.format(
                    "<xsl:value-of select=\"document('%s')\"/>",
                    "http://" + getBaseMsg().getRequestHeader().getURI().getHost() + ":22");
        } catch (URIException e) {
            return new String();
        }
    }

    private boolean requestsLimitReached() {
        return requestsSent >= strengthToRequestCountMap.get(getAttackStrength());
    }

    private String getOtherInfo(XSLTInjectionCheck checkType, String param) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + checkType.ressourceIdentifier + ".otherinfo", param);
    }

    private void raiseAlert(
            HttpMessage msg,
            String param,
            String attack,
            String evidence,
            XSLTInjectionCheck checkType) {
        bingo(
                getRisk(),
                Alert.CONFIDENCE_MEDIUM,
                getName(),
                getDescription(),
                msg.getRequestHeader().getURI().toString(),
                param,
                attack,
                getOtherInfo(checkType, evidence),
                getSolution(),
                evidence,
                getCweId(),
                getWascId(),
                msg);
    }

    @Override
    public int getId() {
        return 90017;
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
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public int getCweId() {
        return 91;
    }

    @Override
    public int getWascId() {
        return 23;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    private class XSLTInjectionCheck {
        String[] payloads;
        String[] responses;
        String ressourceIdentifier;

        public XSLTInjectionCheck(
                String[] payloads, String[] responses, String ressourceIdentifier) {
            this.payloads = payloads;
            this.responses = responses;
            this.ressourceIdentifier = ressourceIdentifier;
        }
    }
}
