/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.grpc;

import java.awt.BorderLayout;
import java.awt.Component;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import org.apache.commons.configuration.FileConfiguration;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.AbstractStringHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestBodyStringHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyStringHttpPanelViewModel;

public class HttpPanelGrpcView implements HttpPanelView, HttpPanelViewModelListener {

    /**
     * Default name used for {@code MessageContainer}.
     *
     * @see org.zaproxy.zap.view.messagecontainer.MessageContainer
     */
    public static final String NAME = "HttpPanelGrpcView";

    private static final String CAPTION_NAME = "GRPC";

    private HttpPanelGrpcArea httpPanelGrpcArea;
    private JPanel mainPanel;

    private AbstractStringHttpPanelViewModel model;

    public HttpPanelGrpcView(AbstractStringHttpPanelViewModel model) {
        httpPanelGrpcArea = new HttpPanelGrpcArea();
        RTextScrollPane scrollPane = new RTextScrollPane(httpPanelGrpcArea);
        scrollPane.setLineNumbersEnabled(false);
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        this.model = model;
        model.addHttpPanelViewModelListener(this);
    }

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            httpPanelGrpcArea.requestFocusInWindow();
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getCaptionName() {
        return CAPTION_NAME;
    }

    @Override
    public String getTargetViewName() {
        return "";
    }

    @Override
    public int getPosition() {
        return 0;
    }

    @Override
    public boolean isEnabled(Message message) {
        //todo: check for grpc string body type
        return true;
    }

    @Override
    public boolean hasChanged() {
        return true;
    }

    @Override
    public JComponent getPane() {
        return mainPanel;
    }

    @Override
    public boolean isEditable() {
        return httpPanelGrpcArea.isEditable();
    }

    @Override
    public void setEditable(boolean editable) {
        httpPanelGrpcArea.setEditable(editable);
    }

    @Override
    public HttpPanelViewModel getModel() {
        return model;
    }

    @Override
    public void save() {
        // this.model.setData(httpPanelGrpcArea.getText());
        // todo: encode before saving
    }

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void dataChanged(HttpPanelViewModelEvent e) {
        String body = ((AbstractStringHttpPanelViewModel) e.getSource()).getData();
        // todo: decode before showing
        httpPanelGrpcArea.setText(body);

        if (!isEditable()) {
            httpPanelGrpcArea.discardAllEdits();
        }
    }
}
