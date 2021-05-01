/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.amf;

import flex.messaging.io.SerializationContext;
import flex.messaging.io.amf.ActionContext;
import flex.messaging.io.amf.ActionMessage;
import flex.messaging.io.amf.AmfMessageDeserializer;
import flex.messaging.io.amf.MessageBody;
import flex.messaging.io.amf.MessageHeader;
import java.awt.BorderLayout;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.text.StringEscapeUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelEvent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModelListener;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.AbstractHttpByteHttpPanelViewModel;

/** @author Colm O'Flaherty */
public abstract class AbstractAMFTextView implements HttpPanelView, HttpPanelViewModelListener {

    protected static final String CONTENT_TYPE_AMF = "application/x-amf";

    public static final String CAPTION_NAME =
            Constant.messages.getString("amf.httppanel.text.view.name");

    private JPanel mainPanel;
    private JLabel amfLabel;

    private AbstractHttpByteHttpPanelViewModel model;

    public AbstractAMFTextView(AbstractHttpByteHttpPanelViewModel model) {
        this.model = model;

        amfLabel = new JLabel();
        amfLabel.setVerticalAlignment(JLabel.TOP);

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(new JScrollPane(amfLabel));

        this.model.addHttpPanelViewModelListener(this);
    }

    @Override
    public void save() {}

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            amfLabel.requestFocusInWindow();
        }
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
        return 1;
    }

    @Override
    public boolean isEnabled(Message aMessage) {
        return isAMF(aMessage);
    }

    @Override
    public boolean hasChanged() {
        return false;
    }

    @Override
    public JComponent getPane() {
        return mainPanel;
    }

    @Override
    public boolean isEditable() {
        return false;
    }

    @Override
    public void setEditable(boolean editable) {}

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public void saveConfiguration(FileConfiguration fileConfiguration) {}

    @Override
    public HttpPanelViewModel getModel() {
        return model;
    }

    @Override
    public void dataChanged(HttpPanelViewModelEvent e) {
        if (!isAMF(model.getMessage())) {
            amfLabel.setText("");
            return;
        }

        SerializationContext serialisationContext = SerializationContext.getSerializationContext();
        serialisationContext.instantiateTypes = false;
        serialisationContext.createASObjectForMissingType = false;

        AmfMessageDeserializer amfDeserialiser = new AmfMessageDeserializer();
        ActionContext actioncontext = new ActionContext();

        StringBuilder amfHumanReadable = new StringBuilder(350);
        amfHumanReadable.append("<html>");

        ActionMessage message = new ActionMessage();
        amfDeserialiser.initialize(
                serialisationContext, new ByteArrayInputStream(model.getData()), null);
        try {
            amfDeserialiser.readMessage(message, actioncontext);
            int headerCount = message.getHeaderCount();
            amfHumanReadable.append(headerCount).append(" headers<br />");

            for (int i = 0; i < headerCount; i++) {
                MessageHeader messageHeader = message.getHeader(i);
                try {
                    Object headerObject = messageHeader.getData();
                    amfHumanReadable
                            .append("Header [")
                            .append(i)
                            .append("]: ")
                            .append(StringEscapeUtils.escapeHtml4(headerObject.toString()))
                            .append("<br />");
                } catch (Exception exeception) {
                    amfHumanReadable.append("Header [").append(i).append("] was unparseable<br />");
                }
            }

            int bodyCount = message.getBodyCount();
            amfHumanReadable.append(bodyCount).append(" bodies<br />");

            // get each message body in turn
            for (int i = 0; i < bodyCount; i++) {
                MessageBody messageBody = message.getBody(i);
                String targetURI = messageBody.getTargetURI();
                String responseURI = messageBody.getResponseURI();
                String method = messageBody.getReplyMethod();

                amfHumanReadable
                        .append("Body [")
                        .append(i)
                        .append("] target URI: [")
                        .append(StringEscapeUtils.escapeHtml4(targetURI))
                        .append("]<br />");
                amfHumanReadable
                        .append("Body [")
                        .append(i)
                        .append("] response URI: [")
                        .append(StringEscapeUtils.escapeHtml4(responseURI))
                        .append("]<br />");
                amfHumanReadable
                        .append("Body [")
                        .append(i)
                        .append("] method: [")
                        .append(StringEscapeUtils.escapeHtml4(method))
                        .append("]<br />");

                try {
                    Object bodyObject = messageBody.getData();
                    String data =
                            (bodyObject instanceof Object[])
                                    ? Arrays.toString((Object[]) bodyObject)
                                    : bodyObject.toString();
                    amfHumanReadable
                            .append("Body [")
                            .append(i)
                            .append("]: ")
                            .append(StringEscapeUtils.escapeHtml4(data))
                            .append("<br />");
                } catch (Exception e1) {
                    amfHumanReadable.append("Body [").append(i).append("] was unparseable<br />");
                }

                // convert the StringBuilder back to a String, and set it.
                amfHumanReadable.append("</html>");
                amfLabel.setText(amfHumanReadable.toString());
            }
        } catch (ClassNotFoundException cnfe) {
            amfLabel.setText(
                    "<html>A class was not found when attempting to read the Action Message from the stream. This should *not* happen</html>");
            return;
        } catch (IOException ioe) {
            amfLabel.setText(
                    "<html>The AMF could not be de-serialised due to an I/O Exception</html>");
            return;
        }
    }

    static boolean isAMF(final Message message) {
        if (!(message instanceof HttpMessage)) {
            return false;
        }

        return CONTENT_TYPE_AMF.equalsIgnoreCase(
                ((HttpMessage) message).getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE));
    }
}
