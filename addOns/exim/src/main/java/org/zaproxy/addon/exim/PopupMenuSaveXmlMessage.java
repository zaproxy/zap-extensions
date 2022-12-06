/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.io.File;
import java.util.Base64;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.XmlUtils;

public class PopupMenuSaveXmlMessage extends AbstractPopupMenuSaveMessage {

    private static final long serialVersionUID = -7217818541206464572L;
    private static final Logger LOG = LogManager.getLogger(PopupMenuSaveXmlMessage.class);
    private static final String STATS_XML_FILE_MSG =
            ExtensionExim.STATS_PREFIX + "save.xml.file.msg";
    private static final String STATS_XML_FILE_MSG_ERROR =
            ExtensionExim.STATS_PREFIX + "save.xml.file.msg.errors";
    private static final String MESSAGE_PREFIX = "exim.savexml.";
    private static final String XML_FILE_EXTENSION = ".xml";

    public PopupMenuSaveXmlMessage() {
        super(MESSAGE_PREFIX, XML_FILE_EXTENSION, PopupMenuSaveXmlMessage::writeOutput);
    }

    private static void writeOutput(
            MessageComponent messageComponent, HttpMessage httpMessage, File file) {
        byte[] bytesHeader = null;
        byte[] bytesBody = null;

        switch (messageComponent) {
            case REQUEST_HEADER:
                bytesHeader = httpMessage.getRequestHeader().toString().getBytes();
                break;

            case REQUEST_BODY:
                bytesBody = httpMessage.getRequestBody().getBytes();
                break;

            case REQUEST:
                bytesHeader = httpMessage.getRequestHeader().toString().getBytes();
                bytesBody = httpMessage.getRequestBody().getBytes();
                break;

            case RESPONSE_HEADER:
                bytesHeader = httpMessage.getResponseHeader().toString().getBytes();
                break;

            case RESPONSE_BODY:
                bytesBody = httpMessage.getResponseBody().getBytes();
                break;

            case RESPONSE:
                bytesHeader = httpMessage.getResponseHeader().toString().getBytes();
                bytesBody = httpMessage.getResponseBody().getBytes();
                break;
        }

        writeToFile(file, bytesHeader, bytesBody, messageComponent);
    }

    private static void writeToFile(
            File file,
            byte[] headersContent,
            byte[] bodyContent,
            MessageComponent messageComponent) {
        try {

            DocumentBuilder docBuilder =
                    XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();

            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("Message");
            doc.appendChild(rootElement);

            Element headers = doc.createElement("Headers");
            rootElement.appendChild(headers);

            Element body = doc.createElement("Body");
            rootElement.appendChild(body);

            if (headersContent != null) {
                headers.appendChild(
                        doc.createTextNode(Base64.getEncoder().encodeToString(headersContent)));
            }

            if (bodyContent != null) {
                body.appendChild(
                        doc.createTextNode(Base64.getEncoder().encodeToString(bodyContent)));
            }

            TransformerFactory transformerFactory = TransformerFactory.newInstance();

            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(file);
            transformer.transform(source, result);
            Stats.incCounter(STATS_XML_FILE_MSG + "." + messageComponent.name());
        } catch (Exception e) {
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "exim.file.save.error", file.getAbsolutePath()));
            LOG.error(e.getMessage(), e);
            Stats.incCounter(STATS_XML_FILE_MSG_ERROR + "." + messageComponent.name());
        }
    }
}
