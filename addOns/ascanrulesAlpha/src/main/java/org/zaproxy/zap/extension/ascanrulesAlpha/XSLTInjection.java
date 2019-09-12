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
 * <p>Need to add more evidence strings for XSLT processors
 *
 * @author CaptainFreak
 * @author ZainabAlShowely
 */
public class XSLTInjection extends AbstractAppParamPlugin {
    private static String[] errorCausingPayloads = {"<"};

    private static String[] vendorReturningPayloads = {
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/>",
        "system-property(\'xsl:vendor\')/>",
        "\"/><xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--",
        "<xsl:value-of select=\"system-property(\'xsl:vendor\')\"/><!--"
    };

    private static String[] xsltVendors = {
        "libxslt", "Microsoft", "Saxonica", "Apache", "Xalan", "SAXON", "Transformiix"
    };

    private static String[] evidenceError = {"compilation error", "XSLT compile error"};

    private static String[] evidencePortScanning = {
        "failed to open stream",
        "Invalid Http response",
        "Connection Refused",
        "No connection could be made because the target machine actively refused it"
    };

    private static final Logger LOG = Logger.getLogger(ApacheRangeHeaderDos.class);

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // initial check verifies if injecting certain strings causes XSLT related
        // errors
        if (checkWithPayloadsAndResponses(msg, param, errorCausingPayloads, evidenceError)) {
            // verifies if we can get the vendor of the processor
            checkWithPayloadsAndResponses(msg, param, vendorReturningPayloads, xsltVendors);
            // verifies if we can get a response relating to ports
            checkPortScanning(msg, param);
        }
    }

    private Boolean checkWithPayloadsAndResponses(
            HttpMessage msg, String param, String[] payloads, String[] responses) {
        for (String payload : payloads) {
            try {
                if (isStop()) { // stop before sending request
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
                        raiseAlert(msg, param, payload, response);
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

    private Boolean checkPortScanning(HttpMessage msg, String param) {
        try {
            String xsltInjec = getXslForPortScan(msg);

            if (isStop()) { // stop before sending request
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Scanner " + getName() + " Stopping.");
                }
                return false;
            }

            msg = sendRequest(msg, param, xsltInjec);

            for (String evidence : evidencePortScanning) {
                if (getBaseMsg().getResponseBody().toString().contains(evidence)) {
                    continue; // skip
                }

                if (msg.getResponseBody().toString().contains(evidence)) {
                    raiseAlert(msg, param, xsltInjec, evidence);
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
            return false;
        }

        return false;
    }

    private HttpMessage sendRequest(HttpMessage msg, String param, String value)
            throws IOException {
        msg = msg.cloneRequest();
        setParameter(msg, param, value);
        sendAndReceive(msg);
        return msg;
    }

    private String getXslForPortScan(HttpMessage msg) throws URIException {
        // only tests one port for now
        return String.format(
                "<xsl:value-of select=\"document('%s')\"/>",
                "http://" + msg.getRequestHeader().getURI().getHost() + ":22");
    }

    private void raiseAlert(HttpMessage msg, String param, String attack, String evidence) {
        bingo(
                getRisk(),
                Alert.CONFIDENCE_MEDIUM,
                getName(),
                getDescription(),
                msg.getRequestHeader().getURI().toString(),
                param,
                attack,
                "",
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
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanalpha.xsltinjection.xslt.refs");
    }

    @Override
    public int getCweId() {
        return 91;
    }

    @Override
    public int getWascId() {
        return 23;
    }
}
