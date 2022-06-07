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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.Predicate;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/**
 * Active scan rule which checks for signs of XSLT injection vulnerabilities with requests
 *
 * @author CaptainFreak
 * @author ZainabAlShowely
 */
public class XsltInjectionScanRule extends AbstractAppParamPlugin {
    private static final String MESSAGE_PREFIX = "ascanbeta.xsltinjection.";

    private enum XSLTInjectionType {
        ERROR(
                new String[] {"<"},
                new String[] {"compilation error", "XSLT compile error", "SAXParseException"},
                new String[] {},
                "error"),
        VENDOR(
                new String[] {
                    "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/>",
                    "system-property(\'xsl:vendor\')/>",
                    "\"/><xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--",
                    "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--"
                },
                new String[] {
                    "libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"
                },
                new String[] {
                    "Microsoft-Azure-Application-Gateway" // Can be returned in a 403 if the gateway
                    // detects a possible attack
                },
                "vendor"),
        PORTSCAN(
                new String[] {},
                new String[] {
                    "failed to open stream",
                    "Invalid Http response",
                    "Connection Refused",
                    "No connection could be made because the target machine actively refused it",
                    "Can not load requested doc"
                },
                new String[] {},
                "portscan"),
        COMMAND_EXEC(
                new String[] {
                    "<xsl:variable name=\"rtobject\" select=\"runtime:getRuntime()\"/>\n"
                            + "<xsl:variable name=\"process\" select=\"runtime:exec($rtobject,'erroneous_command')\"/>\n"
                            + "<xsl:variable name=\"waiting\" select=\"process:waitFor($process)\"/>\n"
                            + "<xsl:value-of select=\"$process\"/>",
                    "<xsl:value-of select=\"php:function('exec','erroneous_command 2>&amp;1')\"/>"
                },
                new String[] {
                    "Cannot run program", "erroneous_command: not found",
                },
                new String[] {},
                "command");

        private String[] payloads;
        private String[] evidences;
        private String[] allowed;
        private String resourceIdentifier;

        XSLTInjectionType(
                String[] payloads,
                String[] responses,
                String[] allowed,
                String resourceIdentifier) {
            this.payloads = payloads;
            this.evidences = responses;
            this.allowed = allowed;
            this.resourceIdentifier = resourceIdentifier;
        }

        private String[] getPayloads(HttpMessage msg) {
            return this == PORTSCAN ? new String[] {getXslForPortScan(msg)} : payloads;
        }

        private String[] getEvidences() {
            return evidences;
        }

        private String[] getAllowed() {
            return allowed;
        }

        private String getResourceIdentifier() {
            return resourceIdentifier;
        }
    }

    private static final Logger LOG = LogManager.getLogger(XsltInjectionScanRule.class);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A01_INJECTION);

    // used to check against the attack strength
    private int requestsSent = 0;
    // map setting the limits associated with each attack strength
    private static Map<AttackStrength, Integer> strengthToRequestCountMap =
            new EnumMap<>(AttackStrength.class);

    static {
        strengthToRequestCountMap.put(AttackStrength.LOW, 6);
        strengthToRequestCountMap.put(AttackStrength.MEDIUM, 12);
        strengthToRequestCountMap.put(AttackStrength.HIGH, 24);
        strengthToRequestCountMap.put(AttackStrength.INSANE, 24);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // goes through all checks and stops if it finds a possible
        // injection
        for (XSLTInjectionType check : XSLTInjectionType.values()) {
            if (tryInjection(param, check)) {
                return;
            }
        }
    }

    private boolean tryInjection(String param, XSLTInjectionType checkType) {
        Predicate<String> filterEvidence =
                ((Predicate<String>) (getBaseMsg().getResponseBody().toString()::contains))
                        .negate();

        String[] relevantEvidence =
                Arrays.stream(checkType.getEvidences())
                        .filter(filterEvidence)
                        .toArray(String[]::new);

        for (String payload : checkType.getPayloads(getBaseMsg())) {
            try {
                if (isStop() || requestsLimitReached()) { // stop before sending request
                    LOG.debug("Scan rule {} stopping.", getName());
                    return true;
                }
                HttpMessage msg = sendRequest(param, payload);
                String body = msg.getResponseBody().toString();

                for (String evidence : relevantEvidence) {
                    if (body.contains(evidence)) {
                        // found a possible injection
                        boolean raiseAlert = true;
                        for (String allow : checkType.getAllowed()) {
                            if (allow.contains(evidence) && body.contains(allow)) {
                                raiseAlert = false;
                                break;
                            }
                        }

                        if (raiseAlert) {
                            raiseAlert(
                                    msg,
                                    param,
                                    payload,
                                    evidence,
                                    checkType.getResourceIdentifier());
                            return true;
                        }
                    }
                }
            } catch (Exception e) {
                LOG.warn(
                        "An error occurred while checking [{}] [{}] for {}. Caught {} {}",
                        getBaseMsg().getRequestHeader().getMethod(),
                        getBaseMsg().getRequestHeader().getURI(),
                        getName(),
                        e.getClass().getName(),
                        e.getMessage());
            }
        }
        return false;
    }

    private HttpMessage sendRequest(String param, String value) throws IOException {
        HttpMessage testMsg = getNewMsg();
        setParameter(testMsg, param, value);
        sendAndReceive(testMsg);
        requestsSent++;
        return testMsg;
    }

    private static String getXslForPortScan(HttpMessage msg) {
        // only tests one port for now
        try {
            return String.format(
                    "<xsl:value-of select=\"document('%s')\"/>",
                    "http://" + msg.getRequestHeader().getURI().getHost() + ":22");
        } catch (URIException e) {
            LOG.warn(
                    "An error occurred while getting Host for {}. Caught {} {}",
                    msg.getRequestHeader().getURI(),
                    e.getClass().getName(),
                    e.getMessage());
            return "";
        }
    }

    private boolean requestsLimitReached() {
        return strengthToRequestCountMap.containsKey(getAttackStrength())
                ? requestsSent >= strengthToRequestCountMap.get(getAttackStrength())
                : false;
    }

    private static String getOtherInfo(String resourceIdentifier, String param) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + resourceIdentifier + ".otherinfo", param);
    }

    private void raiseAlert(
            HttpMessage msg,
            String param,
            String attack,
            String evidence,
            String resourceIdentifier) {
        newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(param)
                .setAttack(attack)
                .setOtherInfo(getOtherInfo(resourceIdentifier, evidence))
                .setEvidence(evidence)
                .setMessage(msg)
                .raise();
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
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }
}
