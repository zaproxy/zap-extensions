/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.saml;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.zaproxy.zap.utils.XmlUtils;

public class SAMLMessage {

    protected static final Logger log = Logger.getLogger(SAMLMessage.class);
    private boolean messageChanged;
    private HttpMessage httpMessage;
    private String samlMessageString;
    private String relayState;
    private Document xmlDocument;
    private Map<String, Attribute> attributeMap;

    /**
     * Create a new saml message object from the httpmessage
     *
     * @param httpMessage The http message that contain the saml message
     * @throws SAMLException
     */
    public SAMLMessage(HttpMessage httpMessage) throws SAMLException {
        this.httpMessage = httpMessage;
        messageChanged = false;
        attributeMap = new LinkedHashMap<>();
        init();
    }

    /**
     * Process and initialize saml attribute values
     *
     * @throws SAMLException
     */
    private void init() throws SAMLException {
        processHTTPMessage();
        buildXMLDocument();
        buildAttributeMap();
    }

    /**
     * Process the httpmessage and get the saml message and relay state
     *
     * @throws SAMLException
     */
    private void processHTTPMessage() throws SAMLException {
        // check whether a saml message
        if (!SAMLUtils.hasSAMLMessage(httpMessage)) {
            throw new SAMLException("Not a SAML Message");
        }

        // get the saml message from the parameters
        for (HtmlParameter urlParameter : httpMessage.getUrlParams()) {
            if (urlParameter.getName().equals("SAMLRequest")
                    || urlParameter.getName().equals("SAMLResponse")) {
                samlMessageString =
                        SAMLUtils.extractSAMLMessage(urlParameter.getValue(), Binding.HTTPRedirect);

            } else if (urlParameter.getName().equals("RelayState")) {
                relayState = urlParameter.getValue();
            }
        }
        for (HtmlParameter formParameter : httpMessage.getFormParams()) {
            if (formParameter.getName().equals("SAMLRequest")
                    || formParameter.getName().equals("SAMLResponse")) {
                samlMessageString =
                        SAMLUtils.extractSAMLMessage(formParameter.getValue(), Binding.HTTPPost);
            } else if (formParameter.getName().equals("RelayState")) {
                relayState = formParameter.getValue();
            }
        }
    }

    /**
     * Build XML document to be manipulated
     *
     * @throws SAMLException
     */
    private void buildXMLDocument() throws SAMLException {
        try {
            DocumentBuilderFactory docBuilderFactory =
                    XmlUtils.newXxeDisabledDocumentBuilderFactory();
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            xmlDocument = docBuilder.parse(new InputSource(new StringReader(samlMessageString)));
            xmlDocument.getDocumentElement().normalize();
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new SAMLException("XML document building failed");
        }
    }

    /** Get the saml attributes from the saml message which are also in the configured list */
    private void buildAttributeMap() {
        // xpath initialization
        XPathFactory xFactory = XPathFactory.newInstance();
        XPath xpath = xFactory.newXPath();
        Set<Attribute> allAttributes = SAMLConfiguration.getInstance().getAvailableAttributes();
        for (Attribute attribute : allAttributes) {
            try {
                XPathExpression expression = xpath.compile(attribute.getxPath());
                Node node = (Node) expression.evaluate(xmlDocument, XPathConstants.NODE);
                if (node != null) { // the attributes that aren't available will be giving null
                    // values
                    String value;
                    if (node instanceof Element) {
                        value = node.getTextContent();
                    } else if (node instanceof Attr) {
                        value = ((Attr) node).getValue();
                    } else {
                        value = node.getNodeValue();
                    }
                    if (value != null && !"".equals(value)) {
                        Attribute newAttrib = attribute.createCopy();
                        newAttrib.setValue(value);
                        attributeMap.put(attribute.getName(), newAttrib);
                    }
                }
            } catch (XPathExpressionException e) {
                log.warn(attribute.getxPath() + " is not a valid XPath", e);
            }
        }
    }

    /**
     * Check whether the values are applicable to the selected attribute
     *
     * @param type Param type that is expected
     * @param value Param value to be tested against
     * @return Object that matches the relevant type is valid, null if invalid
     */
    private Object validateValueType(Attribute.SAMLAttributeValueType type, String value) {
        try {
            switch (type) {
                case String:
                    return value;
                case Decimal:
                    return Double.valueOf(value);
                case Integer:
                    return Integer.parseInt(value);
                case TimeStamp:
                    return LocalDateTime.parse(value);
                default:
                    return value;
            }
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Update XML document with any attributes that were changed */
    private void updateXMLDocument() {
        XPathFactory xFactory = XPathFactory.newInstance();
        XPath xpath = xFactory.newXPath();
        for (Attribute attribute : attributeMap.values()) {
            try {
                Node node =
                        (Node)
                                xpath.compile(attribute.getxPath())
                                        .evaluate(xmlDocument, XPathConstants.NODE);
                if (node != null) { // the attributes that aren't available will be giving null
                    // values
                    if (node instanceof Element) {
                        node.setTextContent(attribute.getValue().toString());
                    } else if (node instanceof Attr) {
                        ((Attr) node).setValue(attribute.getValue().toString());
                    } else {
                        node.setNodeValue(attribute.getValue().toString());
                    }
                }
            } catch (XPathExpressionException e) {
                log.warn(attribute.getxPath() + " is not a valid XPath", e);
            }
        }
        if (SAMLConfiguration.getInstance().getXSWEnabled()) {
            try {
                NodeList nodeList =
                        (NodeList)
                                xpath.compile("/Response//Signature")
                                        .evaluate(xmlDocument, XPathConstants.NODESET);
                for (int i = 0; i < nodeList.getLength(); i++) {
                    Node item = nodeList.item(i);
                    if (item instanceof Element) {
                        item.getParentNode().removeChild(item);
                    }
                }
            } catch (XPathExpressionException e) {
                log.warn("'/Response//Signature' is not a valid XPath", e);
            }
        }
    }

    /** Update the saml message text to the changed xml document */
    private void updateMessage() {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(xmlDocument), new StreamResult(writer));
            samlMessageString = writer.getBuffer().toString().replaceAll("[\\n\\r]", "");
        } catch (TransformerException ignored) {
        }
    }

    /** Rebuild the httpmessage with the changed saml message */
    private void rebuildHttpMessage() {
        try {
            SAMLConfiguration configuration = SAMLConfiguration.getInstance();
            byte[] messageToEncode;
            if (configuration.isDeflateOnSendEnabled()) {
                messageToEncode = SAMLUtils.deflateMessage(samlMessageString);
            } else {
                messageToEncode = samlMessageString.getBytes("UTF-8");
            }

            String encodedSAMLMessage = SAMLUtils.b64Encode(messageToEncode);
            StringBuilder newParamBuilder = new StringBuilder();
            int paramIndex = 0;

            for (HtmlParameter urlParameter : httpMessage.getUrlParams()) {
                if (urlParameter.getName().equals("SAMLRequest")
                        || urlParameter.getName().equals("SAMLResponse")) {
                    String samlParam = urlParameter.getName();
                    newParamBuilder
                            .append(samlParam)
                            .append("=")
                            .append(URLEncoder.encode(encodedSAMLMessage, "UTF-8"));
                } else if (urlParameter.getName().equals("RelayState")) {
                    newParamBuilder
                            .append("RelayState=")
                            .append(URLEncoder.encode(relayState, "UTF-8"));
                } else {
                    newParamBuilder
                            .append(urlParameter.getName())
                            .append("=")
                            .append(URLEncoder.encode(urlParameter.getValue(), "UTF-8"));
                }
                if (paramIndex < httpMessage.getUrlParams().size() - 1) {
                    newParamBuilder.append("&"); // add '&' between params for separation
                }
                paramIndex++;
            } // todo if paramindex>0

            if (httpMessage.getUrlParams().size() > 0) {
                httpMessage.getRequestHeader().getURI().setEscapedQuery(newParamBuilder.toString());
            }

            newParamBuilder = new StringBuilder();
            paramIndex = 0;
            for (HtmlParameter formParameter : httpMessage.getFormParams()) {
                if (formParameter.getName().equals("SAMLRequest")
                        || formParameter.getName().equals("SAMLResponse")) {
                    String samlParam = formParameter.getName();
                    newParamBuilder
                            .append(samlParam)
                            .append("=")
                            .append(URLEncoder.encode(encodedSAMLMessage, "UTF-8"));
                } else if (formParameter.getName().equals("RelayState")) {
                    newParamBuilder
                            .append("RelayState=")
                            .append(URLEncoder.encode(relayState, "UTF-8"));
                } else {
                    newParamBuilder
                            .append(formParameter.getName())
                            .append("=")
                            .append(URLEncoder.encode(formParameter.getValue(), "UTF-8"));
                }
                if (paramIndex < httpMessage.getFormParams().size() - 1) {
                    newParamBuilder.append("&"); // add '&' between params for separation
                }
                paramIndex++;
            }
            httpMessage.setRequestBody(newParamBuilder.toString());
            httpMessage.getRequestHeader().setContentLength(newParamBuilder.length());
        } catch (UnsupportedEncodingException e) {
            log.warn("Unsupported encoding.", e);
        } catch (URIException e) {
            log.warn("Unsupported URI query", e);
        } catch (SAMLException e) {
            log.warn("saml message extraction failed", e);
        }
        messageChanged = false; // the message is permanently modified, can't revert from here on
    }

    /**
     * Change the attribute value to the given new value
     *
     * @param attributeName name of the attribute to be changed
     * @param value new value to be changed to
     * @return whether the change is successful
     */
    public boolean changeAttributeValueTo(String attributeName, String value) {
        if (attributeMap.containsKey(attributeName)) {
            Attribute attribute = attributeMap.get(attributeName);
            Object newValue;
            if (SAMLConfiguration.getInstance().isValidationEnabled()) {
                newValue = validateValueType(attribute.getValueType(), value);
            } else {
                newValue = value;
            }
            if (newValue != null) {
                attribute.setValue(newValue);
                messageChanged = true;
                updateXMLDocument();
                updateMessage();
                return true;
            }
        }
        return false;
    }

    /**
     * Get the new HTTPmessage with changed parameters
     *
     * @return The changed http message if changed, original message if message unchanged.
     */
    public HttpMessage getChangedMessage() {
        if (!messageChanged) {
            return httpMessage;
        } else {
            updateXMLDocument();
            updateMessage();
            rebuildHttpMessage();
        }
        return httpMessage;
    }

    /** Reset any changes to the http message */
    public void resetChanges() {
        if (messageChanged) {
            try {
                processHTTPMessage();
                buildXMLDocument();
                buildAttributeMap();
                messageChanged = false;
            } catch (SAMLException ignored) {
                log.warn(ignored);
            }
        }
    }

    /**
     * Get the relay state
     *
     * @return
     */
    public String getRelayState() {
        return relayState;
    }

    /**
     * Set the relay state
     *
     * @param relayState
     */
    public void setRelayState(String relayState) {
        if (!this.relayState.equals(relayState)) {
            this.relayState = relayState;
            messageChanged = true;
        }
    }

    /**
     * Get the saml message as a formatted XML
     *
     * @return
     */
    public String getSamlMessageString() {
        try {
            Source xmlInput;
            xmlInput = new StreamSource(new StringReader(samlMessageString));

            StringWriter stringWriter = new StringWriter();
            StreamResult xmlOutput = new StreamResult(stringWriter);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute("indent-number", 4);
            Transformer transformer = transformerFactory.newTransformer();

            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(xmlInput, xmlOutput);
            return xmlOutput.getWriter().toString();
        } catch (Exception e) {
            log.warn("error in parsing saml message.", e);
            return samlMessageString;
        }
    }

    /**
     * Set the saml message XML string to the given value
     *
     * @param samlMessageString
     */
    public void setSamlMessageString(String samlMessageString) {
        String trimmedMessage =
                samlMessageString.trim().replaceAll("\n", "").replaceAll("\\s+", " ");
        if (!this.samlMessageString.equals(trimmedMessage)) {
            String oldValue = this.samlMessageString;
            this.samlMessageString = trimmedMessage;
            try {
                buildXMLDocument();
                buildAttributeMap();
                messageChanged = true;
            } catch (SAMLException e) {
                this.samlMessageString = oldValue;
                log.warn("Not a valid saml message", e);
            }
        }
    }

    /**
     * Get the attribute name:value map. This will only contain the configured attributes and their
     * values if they are found in the message
     *
     * @return
     */
    public Map<String, Attribute> getAttributeMap() {
        return attributeMap;
    }

    /**
     * set the attribute name:value map to be updated in the saml message
     *
     * @param attributeMap
     */
    public void setAttributeMap(Map<String, Attribute> attributeMap) {
        this.attributeMap = attributeMap;
    }
}
