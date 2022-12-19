/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal;

import java.util.stream.Stream;
import javax.swing.JComboBox;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.InvalidMessageDataException;
import org.zaproxy.zap.extension.httppanel.component.all.request.RequestAllComponent;

public class CustomHttpPanelRequest extends HttpPanelRequest {

    private static final long serialVersionUID = 1L;

    public CustomHttpPanelRequest(boolean editable, String configurationKey) {
        super(editable, configurationKey);
    }

    @Override
    protected void initComboChangeMethod() {
        if (comboChangeMethod == null) {
            comboChangeMethod = new JComboBox<>();
            comboChangeMethod.setEditable(false);
            comboChangeMethod.addItem(
                    Constant.messages.getString("requester.httppanel.methodchange"));
            Stream.of(HttpRequestHeader.METHODS).sorted().forEach(comboChangeMethod::addItem);
            comboChangeMethod.setMaximumRowCount(HttpRequestHeader.METHODS.length + 1);
            comboChangeMethod.addActionListener(
                    e -> {
                        if (message == null) {
                            comboChangeMethod.setSelectedIndex(0);
                            return;
                        }
                        if (comboChangeMethod.getSelectedIndex() > 0) {
                            updateMethod((HttpMessage) message);
                        }
                    });

            addOptions(comboChangeMethod, OptionsLocation.BEGIN);
            comboChangeMethod.setEnabled(false);
        }
    }

    private void updateMethod(HttpMessage message) {
        try {
            saveData();
        } catch (InvalidMessageDataException e) {
            comboChangeMethod.setSelectedIndex(0);

            StringBuilder warnMessage = new StringBuilder(150);
            warnMessage.append(
                    Constant.messages.getString("requester.httppanel.methodchange.warn"));

            String exceptionMessage = e.getLocalizedMessage();
            if (exceptionMessage != null && !exceptionMessage.isEmpty()) {
                warnMessage.append('\n').append(exceptionMessage);
            }
            View.getSingleton().showWarningDialog(warnMessage.toString());
            return;
        }
        message.mutateHttpMethod((String) comboChangeMethod.getSelectedItem());
        comboChangeMethod.setSelectedIndex(0);
        updateContent();
    }

    public boolean isCombinedView() {
        return this.getCurrentComponent() instanceof RequestAllComponent;
    }
}
