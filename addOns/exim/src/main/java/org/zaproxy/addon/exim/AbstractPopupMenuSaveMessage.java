/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

@SuppressWarnings("serial")
abstract class AbstractPopupMenuSaveMessage extends PopupMenuHttpMessageContainer {

    private static final long serialVersionUID = 8080417865825721164L;

    public enum MessageComponent {
        ALL,
        REQUEST,
        REQUEST_HEADER,
        REQUEST_BODY,
        RESPONSE,
        RESPONSE_HEADER,
        RESPONSE_BODY
    }

    protected AbstractPopupMenuSaveMessage(
            String messagePrefix, String fileExtension, ContentWriter writer) {
        super(Constant.messages.getString(messagePrefix + "popup.option"));

        String popupMenuAll = Constant.messages.getString("exim.popup.option.all");
        String popupMenuBody = Constant.messages.getString("exim.popup.option.body");
        String popupMenuHeader = Constant.messages.getString("exim.popup.option.header");
        String popupMenuRequest = Constant.messages.getString("exim.popup.option.request");
        String popupMenuResponse = Constant.messages.getString("exim.popup.option.response");

        setButtonStateOverriddenByChildren(false);

        SaveMessagePopupMenuItem all =
                new SaveMessagePopupMenuItem(
                        popupMenuAll, MessageComponent.ALL, fileExtension, writer);
        add(all);

        JMenu request = new SaveMessagePopupMenu(popupMenuRequest, MessageComponent.REQUEST);
        SaveMessagePopupMenuItem requestHeader =
                new SaveMessagePopupMenuItem(
                        popupMenuHeader, MessageComponent.REQUEST_HEADER, fileExtension, writer);

        request.add(requestHeader);
        SaveMessagePopupMenuItem requestBody =
                new SaveMessagePopupMenuItem(
                        popupMenuBody, MessageComponent.REQUEST_BODY, fileExtension, writer);
        request.add(requestBody);
        request.addSeparator();
        SaveMessagePopupMenuItem requestAll =
                new SaveMessagePopupMenuItem(
                        popupMenuAll, MessageComponent.REQUEST, fileExtension, writer);
        request.add(requestAll);
        add(request);

        JMenu response = new SaveMessagePopupMenu(popupMenuResponse, MessageComponent.RESPONSE);
        SaveMessagePopupMenuItem responseHeader =
                new SaveMessagePopupMenuItem(
                        popupMenuHeader, MessageComponent.RESPONSE_HEADER, fileExtension, writer);
        response.add(responseHeader);
        SaveMessagePopupMenuItem responseBody =
                new SaveMessagePopupMenuItem(
                        popupMenuBody, MessageComponent.RESPONSE_BODY, fileExtension, writer);
        response.add(responseBody);
        response.addSeparator();
        SaveMessagePopupMenuItem responseAll =
                new SaveMessagePopupMenuItem(
                        popupMenuAll, MessageComponent.RESPONSE, fileExtension, writer);
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

            if (!(messageComponent == MessageComponent.ALL
                    || messageComponent == MessageComponent.REQUEST
                    || messageComponent == MessageComponent.RESPONSE)) {
                throw new IllegalArgumentException("Parameter messageComponent is not supported.");
            }

            this.messageComponent = messageComponent;
        }

        @Override
        protected boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            boolean enabled = false;
            if (MessageComponent.ALL == messageComponent) {
                enabled = true;
            } else if (MessageComponent.REQUEST == messageComponent) {
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

        private final String fileExtension;
        private final String fileDescription;
        private final ContentWriter writer;

        public SaveMessagePopupMenuItem(
                String label,
                MessageComponent messageComponent,
                String fileExtension,
                ContentWriter writer) {
            super(label);

            this.messageComponent = messageComponent;
            this.fileExtension = fileExtension;
            this.fileDescription = fileExtension;
            this.writer = writer;
        }

        @Override
        public boolean isButtonEnabledForSelectedHttpMessage(HttpMessage httpMessage) {
            boolean enabled = false;
            switch (messageComponent) {
                case ALL:
                    enabled = true;
                    break;
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

            writer.writeOutput(messageComponent, httpMessage, file);
        }

        @Override
        public boolean isSafe() {
            return true;
        }

        private File getOutputFile() {
            JFileChooser fileChooser = new EximFileChooser(fileExtension, fileDescription);
            int rc = fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                return fileChooser.getSelectedFile();
            }
            return null;
        }
    }

    public interface ContentWriter {

        void writeOutput(MessageComponent messageComponent, HttpMessage httpMessage, File file);
    }
}
