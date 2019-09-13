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

    private enum XSLTCheckType {
        ERROR,
        VENDOR,
        PORTSCAN
    }

    private static String[] errorCausingPayloads = {"<"};

    private static String[] evidenceError = {"compilation error", "XSLT compile error"};

    private static String[] vendorReturningPayloads = {
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/>",
        "system-property(\'xsl:vendor\')/>",
        "\"/><xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--",
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--"
    };

    private static String[] xsltVendors = {
        "libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"
    };

    private static String[] evidencePortScanning = {
        "failed to open stream",
        "Invalid Http response",
        "Connection Refused",
        "No connection could be made because the target machine actively refused it"
    };

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
        if (tryInjection(msg, param, XSLTCheckType.ERROR)) {
            // verifies if we can get the vendor of the processor
            tryInjection(msg, param, XSLTCheckType.VENDOR);

            // verifies if we can get a response relating to portscan
            tryInjection(msg, param, XSLTCheckType.PORTSCAN);
        }
    }

    private Boolean tryInjection(HttpMessage msg, String param, XSLTCheckType checkType) {
        String[] payloads = getPayloads(checkType);
        String[] responses = getSuspiciousResponses(checkType);
        for (String payload : payloads) {
            try {
                if (isStop() || requestsLimitReached()) { // stop before sending request
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Scanner " + getName() + " Stopping.");
                    }
                    return false;
                }
                msg = sendRequest(msg, param, payload);

                for (String response : responses) {
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

    private String[] getPayloads(XSLTCheckType checkType) {
        switch (checkType) {
            case ERROR:
                return errorCausingPayloads;
            case VENDOR:
                return vendorReturningPayloads;
            case PORTSCAN:
                return new String[] {getXslForPortScan()};
            default:
                return new String[0];
        }
    }

    private String[] getSuspiciousResponses(XSLTCheckType checkType) {
        switch (checkType) {
            case ERROR:
                return evidenceError;
            case VENDOR:
                return xsltVendors;
            case PORTSCAN:
                return evidencePortScanning;
            default:
                return new String[0];
        }
    }

    private String getOtherInfo(XSLTCheckType checkType, String param) {
        String otherInfoSuffix;
        switch (checkType) {
            case ERROR:
                otherInfoSuffix = "error.otherinfo";
                break;
            case VENDOR:
                otherInfoSuffix = "vendor.otherinfo";
                break;
            case PORTSCAN:
                otherInfoSuffix = "portscan.otherinfo";
                break;
            default:
                return new String();
        }

        return Constant.messages.getString(MESSAGE_PREFIX + otherInfoSuffix, param);
    }

    private void raiseAlert(
            HttpMessage msg,
            String param,
            String attack,
            String evidence,
            XSLTCheckType checkType) {
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
}
