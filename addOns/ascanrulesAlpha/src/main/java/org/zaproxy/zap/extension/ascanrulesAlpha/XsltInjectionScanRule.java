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
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.function.Predicate;
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
public class XsltInjectionScanRule extends AbstractAppParamPlugin {
    private static final String MESSAGE_PREFIX = "ascanalpha.xsltinjection.";

    private enum XSLTInjectionType {
        ERROR(
                new String[] {"<"},
                new String[] {"compilation error", "XSLT compile error", "SAXParseException"},
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
                "command");

        private String[] payloads;
        private String[] evidences;
        private String resourceIdentifier;

        XSLTInjectionType(String[] payloads, String[] responses, String resourceIdentifier) {
            this.payloads = payloads;
            this.evidences = responses;
            this.resourceIdentifier = resourceIdentifier;
        }

        private String[] getPayloads(HttpMessage msg) {
            return this == PORTSCAN ? new String[] {getXslForPortScan(msg)} : payloads;
        }

        private String[] getEvidences() {
            return evidences;
        }

        private String getResourceIdentifier() {
            return resourceIdentifier;
        }
    }

    private static final Logger LOG = Logger.getLogger(XsltInjectionScanRule.class);

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
            if (tryInjection(msg, param, check)) {
                return;
            }
        }
    }

    private Boolean tryInjection(HttpMessage msg, String param, XSLTInjectionType checkType) {
        Predicate<String> filterEvidence =
                ((Predicate<String>) (getBaseMsg().getResponseBody().toString()::contains))
                        .negate();

        String[] relevantEvidence =
                Arrays.stream(checkType.getEvidences())
                        .filter(filterEvidence)
                        .toArray(String[]::new);

        for (String payload : checkType.getPayloads(msg)) {
            try {
                if (isStop() || requestsLimitReached()) { // stop before sending request
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Scan rule " + getName() + " Stopping.");
                    }
                    return true;
                }

                msg = sendRequest(msg, param, payload);

                for (String evidence : relevantEvidence) {
                    if (msg.getResponseBody().toString().contains(evidence)) {
                        // found a possible injection
                        raiseAlert(
                                msg, param, payload, evidence, checkType.getResourceIdentifier());
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

    private static String getXslForPortScan(HttpMessage msg) {
        // only tests one port for now
        try {
            return String.format(
                    "<xsl:value-of select=\"document('%s')\"/>",
                    "http://" + msg.getRequestHeader().getURI().getHost() + ":22");
        } catch (URIException e) {
            LOG.warn(
                    "An error occurred while getting Host for "
                            + msg.getRequestHeader().getURI()
                            + " Caught "
                            + e.getClass().getName()
                            + " "
                            + e.getMessage());
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
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }
}
