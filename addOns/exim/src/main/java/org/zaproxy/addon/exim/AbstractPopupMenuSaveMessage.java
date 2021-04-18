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
import javax.swing.filechooser.FileFilter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.popup.PopupMenuHttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

abstract class AbstractPopupMenuSaveMessage extends PopupMenuHttpMessageContainer {

    private static final long serialVersionUID = 8080417865825721164L;

    public static enum MessageComponent {
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

        String fileDescription = Constant.messages.getString(messagePrefix + "file.description");

        String popupMenuAll = Constant.messages.getString("exim.popup.option.all");
        String popupMenuBody = Constant.messages.getString("exim.popup.option.body");
        String popupMenuHeader = Constant.messages.getString("exim.popup.option.header");
        String popupMenuRequest = Constant.messages.getString("exim.popup.option.request");
        String popupMenuResponse = Constant.messages.getString("exim.popup.option.response");

        setButtonStateOverriddenByChildren(false);

        JMenu request = new SaveMessagePopupMenu(popupMenuRequest, MessageComponent.REQUEST);
        SaveMessagePopupMenuItem requestHeader =
                new SaveMessagePopupMenuItem(
                        popupMenuHeader,
                        MessageComponent.REQUEST_HEADER,
                        fileExtension,
                        fileDescription,
                        writer);

        request.add(requestHeader);
        SaveMessagePopupMenuItem requestBody =
                new SaveMessagePopupMenuItem(
                        popupMenuBody,
                        MessageComponent.REQUEST_BODY,
                        fileExtension,
                        fileDescription,
                        writer);
        request.add(requestBody);
        request.addSeparator();
        SaveMessagePopupMenuItem requestAll =
                new SaveMessagePopupMenuItem(
                        popupMenuAll,
                        MessageComponent.REQUEST,
                        fileExtension,
                        fileDescription,
                        writer);
        request.add(requestAll);
        add(request);

        JMenu response = new SaveMessagePopupMenu(popupMenuResponse, MessageComponent.RESPONSE);
        SaveMessagePopupMenuItem responseHeader =
                new SaveMessagePopupMenuItem(
                        popupMenuHeader,
                        MessageComponent.RESPONSE_HEADER,
                        fileExtension,
                        fileDescription,
                        writer);
        response.add(responseHeader);
        SaveMessagePopupMenuItem responseBody =
                new SaveMessagePopupMenuItem(
                        popupMenuBody,
                        MessageComponent.RESPONSE_BODY,
                        fileExtension,
                        fileDescription,
                        writer);
        response.add(responseBody);
        response.addSeparator();
        SaveMessagePopupMenuItem responseAll =
                new SaveMessagePopupMenuItem(
                        popupMenuAll,
                        MessageComponent.RESPONSE,
                        fileExtension,
                        fileDescription,
                        writer);
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

        private final String fileExtension;
        private final String fileDescription;
        private final ContentWriter writer;

        public SaveMessagePopupMenuItem(
                String label,
                MessageComponent messageComponent,
                String fileExtension,
                String fileDescription,
                ContentWriter writer) {
            super(label);

            this.messageComponent = messageComponent;
            this.fileExtension = fileExtension;
            this.fileDescription = fileDescription;
            this.writer = writer;
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

            writer.writeOutput(messageComponent, httpMessage, file);
        }

        @Override
        public boolean isSafe() {
            return true;
        }

        private File getOutputFile() {
            SaveFileChooser fileChooser = new SaveFileChooser();
            int rc = fileChooser.showSaveDialog(View.getSingleton().getMainFrame());
            if (rc == JFileChooser.APPROVE_OPTION) {
                return fileChooser.getSelectedFile();
            }
            return null;
        }

        private class SaveFileChooser extends WritableFileChooser {

            private static final long serialVersionUID = -5743352709683023906L;

            public SaveFileChooser() {
                super(Model.getSingleton().getOptionsParam().getUserDirectory());
                setFileFilter(new SpecificFileFilter());
            }

            @Override
            public void approveSelection() {
                File file = getSelectedFile();
                if (file != null) {
                    String fileName = file.getAbsolutePath();
                    if (!fileName.endsWith(fileExtension)) {
                        fileName += fileExtension;
                        setSelectedFile(new File(fileName));
                    }
                }

                super.approveSelection();
            }
        }

        private class SpecificFileFilter extends FileFilter {

            @Override
            public boolean accept(File file) {
                if (file.isDirectory()) {
                    return true;
                } else if (file.isFile() && file.getName().endsWith(fileExtension)) {
                    return true;
                }
                return false;
            }

            @Override
            public String getDescription() {
                return fileDescription;
            }
        }
    }

    public interface ContentWriter {

        void writeOutput(MessageComponent messageComponent, HttpMessage httpMessage, File file);
    }
}
