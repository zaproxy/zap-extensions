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

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPMessage;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * SOAP XML Injection Active scan rule
 *
 * @author Albertov91
 */
public class SOAPXMLInjectionActiveScanRule extends AbstractAppParamPlugin {

    private static final String MESSAGE_PREFIX = "soap.soapxmlinjection.";

    private static final Logger LOG = Logger.getLogger(SOAPXMLInjectionActiveScanRule.class);

    @Override
    public int getId() {
        return 90029;
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
    public void scan(HttpMessage msg, String paramName, String paramValue) {
        try {
            /* This scan is only applied to SOAP messages. */
            final String request = new String(msg.getRequestBody().getBytes());
            final String reqCharset = msg.getRequestBody().getCharset();
            if (this.isStop()) return;
            if (isSoapMessage(request, reqCharset)) {
                String paramValue2 = paramValue + "_modified";
                String finalValue =
                        paramValue + "</" + paramName + "><" + paramName + ">" + paramValue2;
                /* Request message that contains the modified value. */
                HttpMessage modifiedMsg = craftAttackMessage(msg, paramName, paramValue2);
                if (modifiedMsg == null) return;
                /* Request message that contains the XML code to be injected. */
                HttpMessage attackMsg = craftAttackMessage(msg, paramName, finalValue);
                final String escapedContent = new String(attackMsg.getRequestBody().getBytes());
                final String unescapedContent = StringEscapeUtils.unescapeXml(escapedContent);
                attackMsg.setRequestBody(unescapedContent);
                /* Sends the modified request. */
                if (this.isStop()) return;
                sendAndReceive(modifiedMsg);
                if (this.isStop()) return;
                sendAndReceive(attackMsg);
                if (this.isStop()) return;
                /* Analyzes the response. */
                final String response = new String(attackMsg.getResponseBody().getBytes());
                final String resCharset = attackMsg.getResponseBody().getCharset();
                final HttpMessage originalMsg = getBaseMsg();
                if (this.isStop()) return;
                if (!isSoapMessage(response, resCharset)) {
                    /*
                     * Response has no SOAP format. It is still notified since it is an unexpected
                     * result.
                     */
                    newAlert()
                            .setRisk(Alert.RISK_LOW)
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(finalValue)
                            .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "warn1"))
                            .setMessage(attackMsg)
                            .raise();
                } else if (responsesAreEqual(modifiedMsg, attackMsg)
                        && !(responsesAreEqual(originalMsg, modifiedMsg))) {
                    /*
                     * The attack message has achieved the same result as the modified message, so
                     * XML injection attack worked.
                     */
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setAttack(finalValue)
                            .setOtherInfo(Constant.messages.getString(MESSAGE_PREFIX + "warn2"))
                            .setMessage(attackMsg)
                            .raise();
                }
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    /* Checks whether server response follows a SOAP message format. */
    private boolean isSoapMessage(String content, String charset) {
        SOAPMessage soapMsg = null;
        if (content.length() <= 0) return false;
        MessageFactory factory;
        try {
            factory = MessageFactory.newInstance();
            soapMsg =
                    factory.createMessage(
                            new MimeHeaders(),
                            new ByteArrayInputStream(content.getBytes(Charset.forName(charset))));
            /* Content has been parsed correctly as SOAP content. */
            if (soapMsg != null) return true;
            else return false;
        } catch (Exception e) {
            /*
             * Error when trying to parse as SOAP content. It is considered as a non-SOAP
             * message.
             */
            return false;
        }
    }

    private HttpMessage craftAttackMessage(HttpMessage msg, String paramName, String finalValue) {
        /* Retrieves message configuration to craft a new one. */
        ImportWSDL wsdlSingleton = ImportWSDL.getInstance();
        SOAPMsgConfig soapConfig = wsdlSingleton.getSoapConfig(msg);
        if (soapConfig == null) return null;
        /* XML code injection. */
        boolean isParamChanged = soapConfig.changeParam(paramName, finalValue);
        /* Crafts the message. */
        WSDLCustomParser parser = new WSDLCustomParser();
        if (isParamChanged) return parser.createSoapRequest(soapConfig);
        else return null;
    }

    private boolean responsesAreEqual(HttpMessage original, HttpMessage crafted) {
        final String originalContent = new String(original.getResponseBody().getBytes());
        final String craftedContent = new String(crafted.getResponseBody().getBytes());
        if (originalContent.equals(craftedContent)) return true;
        else return false;
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
