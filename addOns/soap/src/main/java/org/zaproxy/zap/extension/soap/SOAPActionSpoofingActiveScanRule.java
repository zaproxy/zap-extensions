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
package org.zaproxy.zap.extension.soap;

import java.io.IOException;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * SOAP Action Spoofing Active scan rule
 *
 * @author Albertov91
 */
public class SOAPActionSpoofingActiveScanRule extends AbstractAppPlugin {

    private static final String MESSAGE_PREFIX = "soap.soapactionspoofing.";

    private static final Logger LOG = Logger.getLogger(SOAPActionSpoofingActiveScanRule.class);

    public static final int INVALID_FORMAT = -3;
    public static final int FAULT_CODE = -2;
    public static final int EMPTY_RESPONSE = -1;
    public static final int SOAPACTION_IGNORED = 1;
    public static final int SOAPACTION_EXECUTED = 2;

    @Override
    public int getId() {
        return 90026;
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
    public int getCategory() {
        return Category.MISC;
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter
     * for every page
     *
     * @see
     * org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.
     * paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan() {
        try {
            /* Retrieves the original request-response pair. */
            final HttpMessage originalMsg = getBaseMsg();
            /* This scan is only applied to SOAP 1.1 messages. */
            String currentHeader = originalMsg.getRequestHeader().getHeader("SOAPAction");
            if (currentHeader != null && originalMsg.getRequestBody().length() > 0) {
                currentHeader = currentHeader.trim();
                /* Retrieves available actions to try attacks. */
                String[] soapActions = ImportWSDL.getInstance().getSourceSoapActions(originalMsg);

                boolean endScan = false;
                if (soapActions == null || soapActions.length == 0) {
                    // No actions to spoof
                    LOG.info(
                            "Skipping "
                                    + getName()
                                    + " because no actions were found. (URL: "
                                    + originalMsg.getRequestHeader().getURI().toString()
                                    + ")");
                    return;
                }
                for (int j = 0; j < soapActions.length && !endScan; j++) {
                    HttpMessage msg = getNewMsg();
                    /* Skips the original case. */
                    if (!currentHeader.equals(soapActions[j])) {
                        HttpRequestHeader header = msg.getRequestHeader();
                        /* Available actions should be known here from the imported WSDL file. */
                        header.setHeader("SOAPAction", soapActions[j]);
                        msg.setRequestHeader(header);

                        /* Sends the modified request. */
                        if (this.isStop()) return;
                        sendAndReceive(msg);
                        if (this.isStop()) return;

                        /* Checks the response. */
                        int code = scanResponse(msg, originalMsg);
                        if (code > 0) endScan = true;
                        raiseAlert(msg, code);
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "Ignoring matching actions: "
                                            + currentHeader
                                            + " : "
                                            + soapActions[j]);
                        }
                    }
                    if (this.isStop()) return;
                }
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    // Relaxed accessibility for testing.
    int scanResponse(HttpMessage msg, HttpMessage originalMsg) {
        if (msg.getResponseBody().length() == 0) return EMPTY_RESPONSE;
        String responseContent = new String(msg.getResponseBody().getBytes());
        responseContent = responseContent.trim();

        if (responseContent.length() <= 0) {
            return EMPTY_RESPONSE;
        }

        SOAPMessage soapMsg = null;
        try {
            soapMsg = SoapMessageFactory.createMessage(msg.getResponseBody());

            /* Looks for fault code. */
            SOAPBody body = soapMsg.getSOAPBody();
            SOAPFault fault = body.getFault();
            if (fault != null) {
                /*
                 * The web service server has detected something was wrong with the SOAPAction
                 * header so it rejects the request.
                 */
                return FAULT_CODE;
            }

            // Body child.
            NodeList bodyList = body.getChildNodes();
            if (bodyList.getLength() <= 0) return EMPTY_RESPONSE;

            /* Prepares original request to compare it. */
            SOAPMessage originalSoapMsg =
                    SoapMessageFactory.createMessage(originalMsg.getResponseBody());

            /* Comparison between original response body and attack response body. */
            SOAPBody originalBody = originalSoapMsg.getSOAPBody();
            NodeList originalBodyList = originalBody.getChildNodes();
            if (bodyList.getLength() == originalBodyList.getLength()) {
                boolean match = true;
                for (int i = 0; i < bodyList.getLength() && match; i++) {
                    Node node = bodyList.item(i);
                    Node oNode = originalBodyList.item(i);
                    String nodeName = node.getNodeName().trim();
                    String oNodeName = oNode.getNodeName().trim();
                    if (!nodeName.equals(oNodeName)) {
                        match = false;
                    }
                }
                if (match) {
                    /*
                     * Both responses have the same content. The SOAPAction header has been ignored.
                     * SOAPAction Spoofing attack cannot be done if this happens.
                     */
                    return SOAPACTION_IGNORED;
                } else {
                    /*
                     * The SOAPAction header has been processed and an operation which is not the
                     * original one has been executed.
                     */
                    return SOAPACTION_EXECUTED;
                }
            } else {
                /*
                 * The SOAPAction header has been processed and an operation which is not the
                 * original one has been executed.
                 */
                return SOAPACTION_EXECUTED;
            }
        } catch (IOException | SOAPException e) {
            LOG.info("Exception thrown when scanning: ", e);
            return INVALID_FORMAT;
        }
    }

    private void raiseAlert(HttpMessage msg, int code) {
        switch (code) {
            case INVALID_FORMAT:
                newAlert()
                        .setRisk(Alert.RISK_LOW)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setOtherInfo(
                                Constant.messages.getString(MESSAGE_PREFIX + "invalidFormatMsg"))
                        .setMessage(msg)
                        .raise();
                break;
            case FAULT_CODE:
                newAlert()
                        .setRisk(Alert.RISK_LOW)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "faultCodeMsg"))
                        .setMessage(msg)
                        .raise();
                break;
            case EMPTY_RESPONSE:
                newAlert()
                        .setRisk(Alert.RISK_LOW)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setOtherInfo(
                                Constant.messages.getString(MESSAGE_PREFIX + "emptyResponseMsg"))
                        .setMessage(msg)
                        .raise();
                break;
            case SOAPACTION_IGNORED:
                newAlert()
                        .setRisk(Alert.RISK_INFO)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setOtherInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "soapactionIgnoredMsg"))
                        .setMessage(msg)
                        .raise();
                break;
            case SOAPACTION_EXECUTED:
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setOtherInfo(
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "soapactionExecutedMsg"))
                        .setMessage(msg)
                        .raise();
                break;
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 0;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 0;
    }
}
