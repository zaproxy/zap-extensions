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
package org.zaproxy.addon.grpc.internal;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.Base64;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.apache.commons.configuration.FileConfiguration;
import org.fife.ui.rtextarea.RTextScrollPane;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.AbstractByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;

public class HttpPanelGrpcView implements HttpPanelView, HttpPanelViewModelListener {

    public static final String NAME = "HttpPanelGrpcView";

    private static final String CAPTION_NAME = Constant.messages.getString("grpc.panel.view.name");

    private HttpPanelGrpcArea httpPanelGrpcArea;
    private JPanel mainPanel;

    private ProtoBufMessageDecoder protoBufMessageDecoder;

    private ProtoBufMessageEncoder protoBufMessageEncoder;
    private AbstractByteHttpPanelViewModel model;

    public HttpPanelGrpcView(AbstractByteHttpPanelViewModel model) {
        httpPanelGrpcArea = new HttpPanelGrpcArea();
        RTextScrollPane scrollPane = new RTextScrollPane(httpPanelGrpcArea);
        scrollPane.setLineNumbersEnabled(false);
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        this.model = model;
        model.addHttpPanelViewModelListener(this);
        protoBufMessageDecoder = new ProtoBufMessageDecoder();
        protoBufMessageEncoder = new ProtoBufMessageEncoder();
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
        // todo: check for grpc string body type
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
        String text = httpPanelGrpcArea.getText();
        try {
            protoBufMessageEncoder.encode(EncoderUtils.parseIntoList(text));
            byte[] encodedMessage = protoBufMessageEncoder.getOutputEncodedMessage();
            this.model.setData(Base64.getEncoder().encode(encodedMessage));
        } catch (Exception e) {
            showInvalidMessageFormatError(e.getMessage());
        }
    }

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void dataChanged(HttpPanelViewModelEvent e) {
        byte[] body = ((AbstractByteHttpPanelViewModel) e.getSource()).getData();
        httpPanelGrpcArea.setBorder(null);
        try {
            body = DecoderUtils.splitMessageBodyAndStatusCode(body);
            body = Base64.getDecoder().decode(body);
            byte[] payload = DecoderUtils.extractPayload(body);
            if (payload.length == 0) {
                httpPanelGrpcArea.setText("");
            } else {
                protoBufMessageDecoder.decode(payload);
                httpPanelGrpcArea.setText(protoBufMessageDecoder.getDecodedOutput());
            }
        } catch (Exception er) {
            httpPanelGrpcArea.setText(protoBufMessageDecoder.getDecodedOutput() + er.getMessage());
            httpPanelGrpcArea.setBorder(BorderFactory.createLineBorder(Color.RED));
        }
        if (!isEditable()) {
            httpPanelGrpcArea.discardAllEdits();
        }
    }

    private void showInvalidMessageFormatError(String message) {
        JOptionPane.showMessageDialog(
                mainPanel,
                message,
                Constant.messages.getString("grpc.encoder.message.invalid.format.error"),
                JOptionPane.ERROR_MESSAGE);
    }
}
