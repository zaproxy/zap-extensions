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
package org.zaproxy.zap.extension.savexmlmessage;

import java.io.File;
import java.text.MessageFormat;
import java.util.Base64;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.filechooser.FileFilter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

class PopupMenuSaveXMLMessage extends PopupMenuHttpMessageContainer {

    private static final long serialVersionUID = -7217818541206464572L;

    private static final Logger log = Logger.getLogger(PopupMenuSaveXMLMessage.class);

    private static final String POPUP_MENU_LABEL =
            Constant.messages.getString("savexml.popup.option");
    private static final String POPUP_MENU_ALL =
            Constant.messages.getString("savexml.popup.option.all");
    private static final String POPUP_MENU_BODY =
            Constant.messages.getString("savexml.popup.option.body");
    private static final String POPUP_MENU_HEADER =
            Constant.messages.getString("savexml.popup.option.header");
    private static final String POPUP_MENU_REQUEST =
            Constant.messages.getString("savexml.popup.option.request");
    private static final String POPUP_MENU_RESPONSE =
            Constant.messages.getString("savexml.popup.option.response");

    private static final String FILE_DESCRIPTION =
            Constant.messages.getString("savexml.file.description");
    private static final String ERROR_SAVE = Constant.messages.getString("savexml.file.save.error");

    private static final String XML_FILE_EXTENSION = ".xml";

    private static enum MessageComponent {
        REQUEST,
        REQUEST_HEADER,
        REQUEST_BODY,
        RESPONSE,
        RESPONSE_HEADER,
        RESPONSE_BODY
    };

    public PopupMenuSaveXMLMessage() {
        super(POPUP_MENU_LABEL);

        setButtonStateOverriddenByChildren(false);

        JMenu request = new SaveMessagePopupMenu(POPUP_MENU_REQUEST, MessageComponent.REQUEST);
        SaveMessagePopupMenuItem requestHeader =
                new SaveMessagePopupMenuItem(POPUP_MENU_HEADER, MessageComponent.REQUEST_HEADER);

        request.add(requestHeader);
        SaveMessagePopupMenuItem requestBody =
                new SaveMessagePopupMenuItem(POPUP_MENU_BODY, MessageComponent.REQUEST_BODY);
        request.add(requestBody);
        request.addSeparator();
        SaveMessagePopupMenuItem requestAll =
                new SaveMessagePopupMenuItem(POPUP_MENU_ALL, MessageComponent.REQUEST);
        request.add(requestAll);
        add(request);

        JMenu response = new SaveMessagePopupMenu(POPUP_MENU_RESPONSE, MessageComponent.RESPONSE);
        SaveMessagePopupMenuItem responseHeader =
                new SaveMessagePopupMenuItem(POPUP_MENU_HEADER, MessageComponent.RESPONSE_HEADER);
        response.add(responseHeader);
        SaveMessagePopupMenuItem responseBody =
                new SaveMessagePopupMenuItem(POPUP_MENU_BODY, MessageComponent.RESPONSE_BODY);
        response.add(responseBody);
        response.addSeparator();
        SaveMessagePopupMenuItem responseAll =
                new SaveMessagePopupMenuItem(POPUP_MENU_ALL, MessageComponent.RESPONSE);
        response.add(responseAll);
        add(response);
    }

    @Override
    public boolean precedeWithSeparator() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private static class SaveMessagePopupMenu extends PopupMenuHttpMessageContainer {

        private static final long serialVersionUID = -6742362073862968150L;

        private final MessageComponent messageComponent;

        public SaveMessagePopupMenu(String label, MessageComponent messageComponent) {
            super(label);

            setButtonStateOverriddenByChildren(false);

            if (!(messageComponent == MessageComponent.REQUEST
                    || messageComponent == MessageComponent.RESPONSE)) {
                throw new IllegalArgumentException("Parameter messageComponent is not supported.");
            }

            this.messageComponent = messageComponent;
        }

        @Override
        protected boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            boolean enabled = false;
            if (MessageComponent.REQUEST == messageComponent) {
                enabled = !httpMessage.getRequestHeader().isEmpty();
            } else if (MessageComponent.RESPONSE == messageComponent) {
                enabled = !httpMessage.getResponseHeader().isEmpty();
            }

            return enabled;
        }

        @Override
        public boolean isSafe() {
            return true;
        }
    }

    private static class SaveMessagePopupMenuItem extends PopupMenuItemHttpMessageContainer {

        private static final long serialVersionUID = -4108212857830575776L;

        private final MessageComponent messageComponent;

        public SaveMessagePopupMenuItem(String label, MessageComponent messageComponent) {
            super(label);

            this.messageComponent = messageComponent;
        }

        @Override
        public boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            boolean enabled = false;
            switch (messageComponent) {
                case REQUEST_HEADER:
                    enabled = !httpMessage.getRequestHeader().isEmpty();
                    break;
                case REQUEST_BODY:
                case REQUEST:
                    enabled = (httpMessage.getRequestBody().length() != 0);
                    break;
                case RESPONSE_HEADER:
                    enabled = !httpMessage.getResponseHeader().isEmpty();
                    break;
                case RESPONSE_BODY:
                case RESPONSE:
                    enabled = (httpMessage.getResponseBody().length() != 0);
                    break;
                default:
                    enabled = false;
            }

            return enabled;
        }

        @Override
        public void performAction(HttpMessage httpMessage) {
            File file = getOutputFile();
            if (file == null) {
                return;
            }

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

            writeToFile(file, bytesHeader, bytesBody);
        }

        @Override
        public boolean isSafe() {
            return true;
        }
    }

    private static void writeToFile(File file, byte[] headersContent, byte[] bodyContent) {
        try {

            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

            /*Create root element*/
            Document doc = docBuilder.newDocument();
            Element rootElement = doc.createElement("Message");
            doc.appendChild(rootElement);

            /*Create headers element*/
            Element headers = doc.createElement("Headers");
            rootElement.appendChild(headers);

            /*Create body element*/
            Element body = doc.createElement("Body");
            rootElement.appendChild(body);

            /*Base64 Encode headers*/
            if (headersContent != null) {
                headers.appendChild(
                        doc.createTextNode(Base64.getEncoder().encodeToString(headersContent)));
            }
            /*Base64 Encode body*/
            if (bodyContent != null) {
                body.appendChild(
                        doc.createTextNode(Base64.getEncoder().encodeToString(bodyContent)));
            }

            /*Save DOM to file*/
            TransformerFactory transformerFactory = TransformerFactory.newInstance();

            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(file);
            transformer.transform(source, result);

        } catch (Exception e) {
            View.getSingleton()
                    .showWarningDialog(MessageFormat.format(ERROR_SAVE, file.getAbsolutePath()));
            log.error(e.getMessage(), e);
        }
    }

    private static File getOutputFile() {
        SaveRawFileChooser fileChooser = new SaveRawFileChooser();
        int rc = fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
        if (rc == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }
        return null;
    }

    private static class SaveRawFileChooser extends WritableFileChooser {

        private static final long serialVersionUID = -5743352709683023906L;

        public SaveRawFileChooser() {
            super(Model.getSingleton().getOptionsParam().getUserDirectory());
            setFileFilter(new RawFileFilter());
        }

        @Override
        public void approveSelection() {
            File file = getSelectedFile();
            if (file != null) {
                String fileName = file.getAbsolutePath();
                if (!fileName.endsWith(XML_FILE_EXTENSION)) {
                    fileName += XML_FILE_EXTENSION;
                    setSelectedFile(new File(fileName));
                }
            }

            super.approveSelection();
        }
    }

    private static final class RawFileFilter extends FileFilter {

        @Override
        public boolean accept(File file) {
            if (file.isDirectory()) {
                return true;
            } else if (file.isFile() && file.getName().endsWith(XML_FILE_EXTENSION)) {
                return true;
            }
            return false;
        }

        @Override
        public String getDescription() {
            return FILE_DESCRIPTION;
        }
    }
}
