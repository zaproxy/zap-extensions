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
import java.util.List;
import java.util.Locale;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpHeader;
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

    public enum ResponseType {
        INVALID_FORMAT,
        FAULT_CODE,
        EMPTY_RESPONSE,
        SOAPACTION_IGNORED,
        SOAPACTION_EXECUTED
    }

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

    private TableWsdl getTable() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionImportWSDL.class)
                .getTable();
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public void scan() {
        /* Retrieves the original request-response pair. */
        final HttpMessage originalMsg = getBaseMsg();
        String originalSoapAction = SoapAction.extractFrom(originalMsg);
        if (originalSoapAction == null) {
            // Not a SOAP message
            return;
        }

        /* Retrieves available actions to try attacks. */
        List<SoapAction> soapActions;
        try {
            soapActions = getTable().getSourceSoapActions(originalSoapAction);
        } catch (DatabaseException e) {
            LOG.warn("Could not retrieve SOAP actions from the database. Ignoring message.", e);
            return;
        }
        if (soapActions == null || soapActions.isEmpty()) {
            // No actions to spoof
            LOG.info(
                    "Ignoring "
                            + getName()
                            + " because no actions were found. (URL: "
                            + originalMsg.getRequestHeader().getURI().toString()
                            + ")");
            return;
        }
        for (SoapAction soapAction : soapActions) {
            if (isStop()) {
                return;
            }
            HttpMessage msg = getNewMsg();
            /* Skips the original case. */
            if (originalSoapAction.trim().equals(soapAction.getAction())) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug(
                            "Ignoring matching actions: "
                                    + originalSoapAction
                                    + " : "
                                    + soapAction.getAction());
                }
                continue;
            }
            HttpRequestHeader header = msg.getRequestHeader();
            boolean isSoapVersionOne = false;
            /* Available actions should be known here from the imported WSDL file. */
            if (originalMsg.getRequestHeader().getHeader("SOAPAction") != null) {
                header.setHeader("SOAPAction", soapAction.getAction());
                isSoapVersionOne = true;
            } else {
                header.setHeader(
                        HttpHeader.CONTENT_TYPE,
                        "application/soap+xml;charset=UTF-8;action=" + soapAction.getAction());
            }

            /* Sends the modified request. */
            try {
                sendAndReceive(msg);
            } catch (IOException e) {
                LOG.warn("Could not send modified SOAP request.");
                return;
            }
            /* Checks the response. */
            ResponseType code = scanResponse(msg, originalMsg);
            String otherAlertInfo =
                    Constant.messages.getString(
                            MESSAGE_PREFIX + "alertInfo",
                            isSoapVersionOne ? "1" : "2",
                            originalSoapAction,
                            soapAction.getAction());
            raiseAlert(msg, code, otherAlertInfo);
            if (code == ResponseType.SOAPACTION_IGNORED
                    || code == ResponseType.SOAPACTION_EXECUTED) {
                return;
            }
        }
    }

    // Relaxed accessibility for testing.
    ResponseType scanResponse(HttpMessage msg, HttpMessage originalMsg) {
        if (msg.getResponseBody().length() == 0) return ResponseType.EMPTY_RESPONSE;
        String responseContent = new String(msg.getResponseBody().getBytes());
        responseContent = responseContent.trim();

        if (responseContent.length() <= 0) {
            return ResponseType.EMPTY_RESPONSE;
        }

        try {
            SOAPMessage soapMsg = SoapMessageFactory.createMessage(msg.getResponseBody());
            if (soapMsg == null) {
                return ResponseType.INVALID_FORMAT;
            }
            /* Looks for fault code. */
            SOAPBody body = soapMsg.getSOAPBody();
            SOAPFault fault = body.getFault();
            if (fault != null) {
                /*
                 * The web service server has detected something was wrong with the SOAPAction
                 * header so it rejects the request.
                 */
                return ResponseType.FAULT_CODE;
            }

            // Body child.
            NodeList bodyList = body.getChildNodes();
            if (bodyList.getLength() <= 0) return ResponseType.EMPTY_RESPONSE;

            /* Prepares original request to compare it. */
            SOAPMessage originalSoapMsg =
                    SoapMessageFactory.createMessage(originalMsg.getResponseBody());
            if (originalSoapMsg == null) {
                return ResponseType.INVALID_FORMAT;
            }

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
                    return ResponseType.SOAPACTION_IGNORED;
                } else {
                    /*
                     * The SOAPAction header has been processed and an operation which is not the
                     * original one has been executed.
                     */
                    return ResponseType.SOAPACTION_EXECUTED;
                }
            } else {
                /*
                 * The SOAPAction header has been processed and an operation which is not the
                 * original one has been executed.
                 */
                return ResponseType.SOAPACTION_EXECUTED;
            }
        } catch (IOException | SOAPException e) {
            LOG.info("Exception thrown when scanning: ", e);
            return ResponseType.INVALID_FORMAT;
        }
    }

    private void raiseAlert(HttpMessage msg, ResponseType code, String otherInfo) {
        int risk;
        switch (code) {
            case INVALID_FORMAT:
            case FAULT_CODE:
            case EMPTY_RESPONSE:
                risk = Alert.RISK_LOW;
                break;
            case SOAPACTION_EXECUTED:
                risk = Alert.RISK_MEDIUM;
                break;
            case SOAPACTION_IGNORED:
            default:
                risk = Alert.RISK_INFO;
                break;
        }
        otherInfo =
                Constant.messages.getString(MESSAGE_PREFIX + code.name().toLowerCase(Locale.ROOT))
                        + otherInfo;
        newAlert()
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setOtherInfo(otherInfo)
                .setMessage(msg)
                .raise();
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
