/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.fieldenumeration;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.ButtonGroup;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.model.ParameterParser;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.utils.ZapTextField;

public class FieldEnumeration extends AbstractDialog {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(FieldEnumeration.class);
    private static final String US_ASCII_CHARSET_NAME = "US-ASCII";
    private static final String UTF_8_CHARSET_NAME = "UTF-8";
    private HttpSender httpSender;

    private JPanel primaryPanel = null;
    private JTabbedPane tabbedPane = new JTabbedPane();
    private JPanel formPanel = new JPanel();
    private JPanel contentPanel = null;
    private JLabel printURL = new JLabel();
    private DefaultTableModel model = new DefaultTableModel();
    private JTable jTable = new JTable();
    private JButton buttonOK = new JButton(Constant.messages.getString("fieldenumeration.submit"));
    private JLabel denylistLabel =
            new JLabel(Constant.messages.getString("fieldenumeration.denylist"));
    private JTextArea denyTextArea = new JTextArea(5, 5);
    private JTextArea allowTextArea = new JTextArea(5, 5);
    private JLabel allowlistLabel =
            new JLabel(Constant.messages.getString("fieldenumeration.allowlist"));
    private JComboBox<String> params = new JComboBox<>();
    private JComboBox<String> charSets = new JComboBox<>();
    private String selectedChars = null;
    private GridBagConstraints c1 = new GridBagConstraints();
    private JTextField preField = new JTextField();
    private JTextField lowerR = new JTextField();
    private JTextField highR = new JTextField();
    private JTextField postField = new JTextField();
    private Font panelFont = new Font("Courier", Font.BOLD, 12);
    private JScrollPane denyScrollPane = new JScrollPane(denyTextArea);
    private JScrollPane allowScrollPane = new JScrollPane(allowTextArea);
    private JProgressBar jProgressBar = new JProgressBar();

    private ButtonGroup group = new ButtonGroup();
    private JTextField regex = new JTextField(20);

    private List<NameValuePair> listParam = new ArrayList<>();
    private HistoryReference historyRef;
    private HttpMessage msg;
    private String field = null;

    public FieldEnumeration() throws HeadlessException {
        super();
        init();
    }

    public FieldEnumeration(Frame arg0, boolean arg1) throws HeadlessException {
        super(arg0, arg1);
        init();
    }

    private void persistAndShowMessage(final HttpMessage httpMessage) {
        if (!EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> persistAndShowMessage(httpMessage));
            return;
        }

        try {
            Session session = Model.getSingleton().getSession();
            HistoryReference ref =
                    new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, httpMessage);
            final ExtensionHistory extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
            if (extHistory != null) {
                extHistory.addHistory(ref);
            }
            SessionStructure.addPath(Model.getSingleton(), ref, httpMessage);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist message sent:", e);
        }
    }

    public List<NameValuePair> getParamList() {
        return listParam;
    }

    protected String getEscapedName(String name) {
        return name != null ? AbstractPlugin.getURLEncode(name) : "";
    }

    private String setParameter(HttpMessage msg, String name, String value, boolean escaped) {
        ParameterParser parser;
        parser =
                Model.getSingleton()
                        .getSession()
                        .getFormParamParser(msg.getRequestHeader().getURI().toString());
        StringBuilder sb = new StringBuilder("");
        String encodedValue = "";

        try {
            encodedValue =
                    (escaped) ? value : URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Ignore
        }

        NameValuePair pair;
        boolean isAppended = true;

        for (int i = 0; i < getParamList().size(); i++) {
            pair = getParamList().get(i);

            if (pair.getName().equals(name)) {
                isAppended = paramAppend(sb, getEscapedName(name), encodedValue, parser);
            } else {
                try {
                    isAppended =
                            paramAppend(
                                    sb,
                                    getEscapedName(pair.getName()),
                                    URLEncoder.encode(
                                            pair.getValue(), StandardCharsets.UTF_8.name()),
                                    parser);
                } catch (UnsupportedEncodingException ignore) {
                    // Ignore
                }
            }

            if (isAppended && i < getParamList().size() - 1) {
                sb.append(parser.getDefaultKeyValuePairSeparator());
            }
        }

        if (sb.length() == 0) {
            // No original query string
            sb.append(encodedValue);
        }
        String query = sb.toString();
        msg.getRequestBody().setBody(query);
        return query;
    }

    private boolean paramAppend(
            StringBuilder sb, String name, String value, ParameterParser parser) {
        boolean isEdited = false;

        if (name != null) {
            sb.append(name);
            isEdited = true;
        }

        if (value != null) {
            sb.append(parser.getDefaultKeyValueSeparator());
            sb.append(value);
            isEdited = true;
        }

        return isEdited;
    }

    private void init() {
        this.setTitle(Constant.messages.getString("fieldenumeration.field.popup"));
        this.setContentPane(getContentPanel());

        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(400, 400);
        }

        pack();
    }

    private void start(
            final int start,
            final int end,
            final String pre,
            final String post,
            final String regStr) {

        final StringBuilder iChars = new StringBuilder();
        final StringBuilder lChars = new StringBuilder();

        final Runnable runnable =
                () -> {
                    // Current runnable code
                    for (int ch = start; ch < end; ch++) {
                        jProgressBar.setValue(ch);

                        String chars = Character.toString((char) ch);

                        String letter;

                        if (pre != null && post != null) {
                            letter = pre.concat(chars);
                            letter = letter.concat(post);
                        } else if (pre != null && post == null) {
                            letter = pre.concat(chars);
                        } else if (pre == null && post != null) {
                            letter = chars.concat(post);
                        } else {
                            letter = chars;
                        }

                        HttpMessage message = msg.cloneRequest();

                        setParameter(message, field, letter, false);
                        message.getRequestHeader()
                                .setContentLength(message.getRequestBody().length());
                        try {
                            gethttpSender().sendAndReceive(message, false);
                        } catch (IOException ioe) {
                            throw new IllegalArgumentException(
                                    "IO error in sending request: "
                                            + ioe.getClass()
                                            + ": "
                                            + ioe.getMessage(),
                                    ioe);
                        }
                        String response = message.getResponseBody().toString();
                        Pattern pattern = Pattern.compile(regStr);
                        Matcher matcher = pattern.matcher(response);
                        if (matcher.find()) {
                            model.addRow(
                                    new Object[] {
                                        letter,
                                        Constant.messages.getString("fieldenumeration.failed")
                                    });
                            iChars.append(letter).append(", ");
                        } else {
                            model.addRow(
                                    new Object[] {
                                        letter,
                                        Constant.messages.getString("fieldenumeration.success")
                                    });
                            lChars.append(letter).append(", ");
                        }
                        persistAndShowMessage(message);
                    }
                    denyTextArea.append(iChars.toString());
                    allowTextArea.append(lChars.toString());
                };

        Thread thread = new Thread(runnable);
        thread.start();
    }

    private JPanel getPrimaryPanel() {
        if (primaryPanel == null) {
            int y = 0;
            primaryPanel = new JPanel();
            primaryPanel.setLayout(new GridBagLayout());
            c1.fill = GridBagConstraints.HORIZONTAL;
            primaryPanel.setSize(new Dimension(600, 600));
            c1.gridx = 0;
            c1.gridy = y;
            JLabel url = new JLabel(Constant.messages.getString("fieldenumeration.url"));
            url.setFont(panelFont);
            primaryPanel.add(url, c1);
            c1.anchor = GridBagConstraints.NORTH;
            c1.gridx = 1;
            c1.gridy = y++;
            primaryPanel.add(printURL, c1);
            c1.gridwidth = 2;
            c1.gridx = 0;
            c1.gridy = y++;
            JLabel enterRegex =
                    new JLabel(Constant.messages.getString("fieldenumeration.enter.regex"));
            enterRegex.setFont(panelFont);
            primaryPanel.add(enterRegex, c1);
            c1.gridy = y++;
            primaryPanel.add(regex, c1);
            c1.gridy = y++;
            JLabel selectChars =
                    new JLabel(Constant.messages.getString("fieldenumeration.select.chars"));
            selectChars.setFont(panelFont);
            primaryPanel.add(selectChars, c1);
            charSets.addItem(Constant.messages.getString("fieldenumeration.ascii"));
            charSets.addItem(Constant.messages.getString("fieldenumeration.utf"));
            charSets.addItem(Constant.messages.getString("fieldenumeration.ebcidic"));
            c1.gridy = y++;
            primaryPanel.add(charSets, c1);
            c1.gridy = y++;
            JLabel formParam =
                    new JLabel(Constant.messages.getString("fieldenumeration.form.param"));
            formParam.setFont(panelFont);
            primaryPanel.add(formParam, c1);
            formParam.setFont(panelFont);
            primaryPanel.add(formParam, c1);
            c1.gridy = y++;
            primaryPanel.add(params, c1);
            c1.gridy = y++;
            JLabel prefix = new JLabel(Constant.messages.getString("fieldenumeration.prefix"));
            prefix.setFont(panelFont);
            primaryPanel.add(prefix, c1);
            c1.gridy = y++;
            preField.setColumns(10);
            primaryPanel.add(preField, c1);
            c1.gridy = y++;
            JLabel postfix = new JLabel(Constant.messages.getString("fieldenumeration.postfix"));
            postfix.setFont(panelFont);
            primaryPanel.add(postfix, c1);
            c1.gridy = y++;
            postField.setColumns(10);
            primaryPanel.add(postField, c1);
            c1.gridy = y++;
            JLabel range = new JLabel(Constant.messages.getString("fieldenumeration.range"));
            range.setFont(panelFont);
            primaryPanel.add(range, c1);
            c1.gridy = y++;
            JLabel fromR = new JLabel(Constant.messages.getString("fieldenumeration.range.from"));
            fromR.setFont(panelFont);
            primaryPanel.add(fromR, c1);
            c1.gridy = y++;
            lowerR.setColumns(10);
            primaryPanel.add(lowerR, c1);
            c1.gridy = y++;
            JLabel toR = new JLabel(Constant.messages.getString("fieldenumeration.range.to"));
            toR.setFont(panelFont);
            primaryPanel.add(toR, c1);
            c1.gridy = y++;
            highR.setColumns(10);
            primaryPanel.add(highR, c1);
            c1.gridy = y++;
            primaryPanel.add(buttonOK, c1);
            c1.gridy = y++;
            jProgressBar.setStringPainted(true);
            primaryPanel.add(jProgressBar, c1);
            c1.gridy = y++;
            denylistLabel.setFont(panelFont);
            primaryPanel.add(denylistLabel, c1);
            c1.gridy = y++;
            primaryPanel.add(denyScrollPane, c1);
            c1.gridy = y++;
            allowlistLabel.setFont(panelFont);
            primaryPanel.add(allowlistLabel, c1);
            c1.gridy = y++;
            primaryPanel.add(allowScrollPane, c1);
        }
        return primaryPanel;
    }

    private JPanel getContentPanel() {
        if (contentPanel == null) {
            contentPanel = new JPanel();
            contentPanel.setSize(new Dimension(600, 600));
            contentPanel.setVisible(true);
            tabbedPane.add(
                    Constant.messages.getString("fieldenumeration.field.popup"), getPrimaryPanel());

            tabbedPane.add(
                    Constant.messages.getString("fieldenumeration.form.fields.tab.name"),
                    formPanel);

            contentPanel.add(tabbedPane);

            buttonOK.addActionListener(
                    event -> {
                        field = (String) params.getSelectedItem();
                        selectedChars = (String) charSets.getSelectedItem();
                        String pre = preField.getText();
                        String post = postField.getText();
                        String regexStr = regex.getText();
                        // Result tab
                        model.addColumn(Constant.messages.getString("fieldenumeration.chars"));
                        model.addColumn(Constant.messages.getString("fieldenumeration.result"));
                        jTable.setModel(model);
                        // end
                        JTextField tf = new JTextField();
                        tf.setEditable(false);
                        DefaultCellEditor editor = new DefaultCellEditor(tf);
                        jTable.setDefaultEditor(FieldEnumeration.class, editor);

                        httpSender = gethttpSender();
                        try {
                            msg = historyRef.getHttpMessage().cloneRequest();
                        } catch (HttpMalformedHeaderException | DatabaseException mhe) {
                            throw new IllegalArgumentException("Malformed header error.", mhe);
                        }
                        // This block seems unnecessary, originalNvp was being passed to start but
                        // then not used
                        // Leaving until someone decides to finish this add-on
                        //                        NameValuePair originalNvp = null;
                        //                        for (NameValuePair parameter : listParam) {
                        //                            if (field.equals(parameter.getName())) {
                        //                                originalNvp = parameter;
                        //                                break;
                        //                            }
                        //                        }

                        int start = 0;
                        int end = 0;

                        if (!lowerR.getText().isEmpty() && !highR.getText().isEmpty()) {
                            try {
                                start = Integer.parseInt(lowerR.getText());
                            } catch (NumberFormatException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                            try {
                                end = Integer.parseInt(highR.getText());
                            } catch (NumberFormatException e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                        } else {
                            if (selectedChars.equals(US_ASCII_CHARSET_NAME)) {
                                start = 0;
                                end = 128;
                            } else if (selectedChars.equals(UTF_8_CHARSET_NAME)) {
                                start = 0;
                                end = 513;
                            } else {
                                start = 0;
                                end = 226;
                            }
                        }

                        denyTextArea.setText("");
                        allowTextArea.setText("");

                        start(start, end, pre, post, regexStr);
                    });

            pack();
        }
        return contentPanel;
    }

    public HistoryReference getHistoryRef() {
        return historyRef;
    }

    private HttpSender gethttpSender() {
        if (httpSender == null) {
            httpSender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            false,
                            HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return httpSender;
    }

    public void setHistoryRef(HistoryReference historyRef) {
        this.historyRef = historyRef;
        printURL.setText(historyRef.getURI().toString());

        formPanel.removeAll();
        params.removeAllItems();
        formPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbcForm = new GridBagConstraints();
        gbcForm.gridy = 0;
        gbcForm.anchor = GridBagConstraints.NORTH;

        try {
            listParam =
                    Model.getSingleton()
                            .getSession()
                            .getParameters(historyRef.getHttpMessage(), HtmlParameter.Type.form);
            for (NameValuePair parameter : listParam) {
                JRadioButton button = new JRadioButton(parameter.getName());
                group.add(button);
                gbcForm.gridx = 0;
                gbcForm.fill = GridBagConstraints.NONE;
                formPanel.add(button, gbcForm);
                params.addItem(parameter.getName());

                ZapTextField textField = new ZapTextField(parameter.getValue());
                textField.setColumns(10);

                gbcForm.gridx = 1;
                gbcForm.fill = GridBagConstraints.HORIZONTAL;
                formPanel.add(textField, gbcForm);

                gbcForm.gridy++;
            }
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
