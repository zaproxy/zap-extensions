/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.tokengen;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.TreeSet;
import java.util.Vector;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.params.HtmlParameterStats;

@SuppressWarnings("serial")
public class GenerateTokensDialog extends AbstractDialog {

    private static String[] PARAM_TYPES = {
        HtmlParameter.Type.cookie.name(),
        HtmlParameter.Type.form.name(),
        HtmlParameter.Type.url.name()
    };
    private static final long serialVersionUID = 1L;
    private JPanel jPanel = null;

    private JComboBox<String> numTokens = null;
    private JComboBox<String> paramType = null;
    private JComboBox<String> paramName = null;
    private JLabel removeCookiesLabel = null;
    private JCheckBox shouldRemoveCookieCheckBox = null;
    private JButton cancelButton = null;
    private JButton startButton = null;

    private ExtensionTokenGen extension = null;
    private HttpMessage httpMessage = null;
    private TokenGenerator generator = null;

    private Vector<String> cookieParams = new Vector<>();
    private Vector<String> formParams = new Vector<>();
    private Vector<String> urlParams = new Vector<>();

    private static Logger log = LogManager.getLogger(GenerateTokensDialog.class);

    private ResourceBundle messages;

    /** @throws HeadlessException */
    public GenerateTokensDialog(ResourceBundle messages) throws HeadlessException {
        super();
        this.messages = messages;
        initialize();
        this.pack();
    }

    /** This method initializes this */
    private void initialize() {
        this.setContentPane(getJTabbed());
        this.setTitle(messages.getString("tokengen.generate.title"));
    }

    /**
     * This method initializes jPanel
     *
     * @return javax.swing.JPanel
     */
    private JPanel getJTabbed() {
        if (jPanel == null) {
            jPanel = new JPanel();
            jPanel.setLayout(new GridBagLayout());

            jPanel.add(
                    new JLabel(messages.getString("tokengen.generate.label.type")),
                    getGBC(0, 0, 1, 0.25D));
            jPanel.add(getParamType(), getGBC(1, 0, 3, 0.0D));
            jPanel.add(
                    new JLabel(messages.getString("tokengen.generate.label.name")),
                    getGBC(0, 1, 1, 0.25D));
            jPanel.add(getParamName(), getGBC(1, 1, 3, 0.0D));
            jPanel.add(getRemoveCookiesLabel(), getGBC(0, 2, 1, 0.25D));
            jPanel.add(getShouldRemoveCookieCheckBox(), getGBC(1, 2, 3, 0.0D));
            jPanel.add(
                    new JLabel(messages.getString("tokengen.generate.label.numTokens")),
                    getGBC(0, 3, 1, 0.25D));
            jPanel.add(getNumTokensField(), getGBC(1, 3, 3, 0.0D));
            jPanel.add(getCancelButton(), getGBC(2, 4, 1, 0.25));
            jPanel.add(getStartButton(), getGBC(3, 4, 1, 0.25));
        }
        return jPanel;
    }

    private JButton getCancelButton() {
        if (cancelButton == null) {
            cancelButton = new JButton();
            cancelButton.setText(messages.getString("tokengen.generate.button.cancel"));
            cancelButton.addActionListener(
                    e -> {
                        if (generator != null) {
                            generator.stopGenerating();
                            generator = null;
                        } else setVisible(false);
                    });
        }
        return cancelButton;
    }

    private JButton getStartButton() {
        if (startButton == null) {
            startButton = new JButton();
            startButton.setText(messages.getString("tokengen.generate.button.generate"));
            startButton.addActionListener(
                    e -> {
                        log.debug("getStartButton action {}", e);
                        int numGen = -1;
                        try {
                            numGen =
                                    Integer.parseInt(
                                            (String) getNumTokensField().getSelectedItem());
                        } catch (NumberFormatException nfe) {
                            View.getSingleton()
                                    .showWarningDialog(
                                            GenerateTokensDialog.this,
                                            messages.getString("tokengen.generate.num.error"));
                            return;
                        }
                        Mode mode = Control.getSingleton().getMode();
                        if (Mode.safe.equals(mode)) {
                            View.getSingleton()
                                    .showWarningDialog(
                                            GenerateTokensDialog.this,
                                            Constant.messages.getString(
                                                    "tokengen.generate.error.mode.safe"));
                            return;
                        } else if (Mode.protect.equals(mode)) {
                            if (!httpMessage.isInScope()) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                GenerateTokensDialog.this,
                                                Constant.messages.getString(
                                                        "tokengen.generate.error.mode.protected",
                                                        httpMessage.getRequestHeader().getURI()));
                                return;
                            }
                        }

                        extension.startTokenGeneration(
                                httpMessage,
                                numGen,
                                new HtmlParameterStats(
                                        "",
                                        (String) getParamName().getSelectedItem(),
                                        HtmlParameter.Type.valueOf(
                                                (String) getParamType().getSelectedItem()),
                                        null,
                                        null),
                                getShouldRemoveCookieCheckBox().isSelected()
                                        && getShouldRemoveCookieCheckBox()
                                                .isEnabled()); // Could be selected but not
                        // enabled for non-cookie types
                        setVisible(false);
                    });
        }
        return startButton;
    }

    private GridBagConstraints getGBC(int x, int y, int width, double weightx) {
        return this.getGBC(x, y, width, weightx, 0.0);
    }

    private GridBagConstraints getGBC(int x, int y, int width, double weightx, double weighty) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = x;
        gbc.gridy = y;
        gbc.insets = new java.awt.Insets(1, 5, 1, 5);
        gbc.anchor = java.awt.GridBagConstraints.NORTHWEST;
        gbc.fill = java.awt.GridBagConstraints.BOTH;
        gbc.weightx = weightx;
        gbc.weighty = weighty;
        gbc.gridwidth = width;
        return gbc;
    }
    /*
    private FilteredZapTextField getGenerateField() {
    	if (generateField == null) {
    		generateField = new FilteredZapTextField("0123456789");
    		generateField.setText("10000");
    	}
    	return generateField;
    }
    */

    private JComboBox<String> getNumTokensField() {
        if (numTokens == null) {
            numTokens = new JComboBox<>();
            numTokens.setEditable(true);
            numTokens.addItem("10000");
            numTokens.addItem("20000");
            numTokens.addItem("30000");
            numTokens.addItem("40000");
            numTokens.addItem("50000");
            numTokens.addItem("60000");
            numTokens.addItem("70000");
            numTokens.addItem("80000");
            numTokens.addItem("90000");
            numTokens.addItem("100000");
            numTokens.setSelectedIndex(1);
        }
        return numTokens;
    }

    public void setMessage(HttpMessage httpMessage) {
        this.httpMessage = httpMessage;

        cookieParams = new Vector<>();
        TreeSet<HtmlParameter> params = httpMessage.getCookieParams();
        Iterator<HtmlParameter> cIter = params.iterator();
        while (cIter.hasNext()) {
            String cookieName = cIter.next().getName();
            if (!cookieParams.contains(cookieName)) {
                cookieParams.add(cookieName);
            }
        }

        urlParams = new Vector<>();
        params = httpMessage.getUrlParams();
        Iterator<HtmlParameter> uIter = params.iterator();
        while (uIter.hasNext()) {
            urlParams.add(uIter.next().getName());
        }

        formParams = extension.getFormInputFields(httpMessage);

        getParamType().setEnabled(true);
        getStartButton().setEnabled(true);

        if (cookieParams.size() > 0) {
            getParamType().setSelectedItem(HtmlParameter.Type.cookie.name());
        } else if (formParams.size() > 0) {
            getParamType().setSelectedItem(HtmlParameter.Type.form.name());
        } else if (urlParams.size() > 0) {
            getParamType().setSelectedItem(HtmlParameter.Type.url.name());
        } else {
            // Nothing to see here...
            getParamType().setEnabled(false);
            getStartButton().setEnabled(false);
        }
    }

    private JComboBox<String> getParamType() {
        if (paramType == null) {
            paramType = new JComboBox<>(PARAM_TYPES);
            paramType.addActionListener(
                    e -> {
                        if ("comboBoxChanged".equals(e.getActionCommand())) {
                            getParamName().removeAllItems();
                            Vector<String> params = null;
                            if (HtmlParameter.Type.cookie
                                    .name()
                                    .equals(paramType.getSelectedItem())) {
                                params = cookieParams;
                            } else if (HtmlParameter.Type.form
                                    .name()
                                    .equals(paramType.getSelectedItem())) {
                                params = formParams;
                            } else if (HtmlParameter.Type.url
                                    .name()
                                    .equals(paramType.getSelectedItem())) {
                                params = urlParams;
                            }
                            if (params != null) {
                                for (String param : params) {
                                    getParamName().addItem(param);
                                }
                            }
                            getParamName().setEnabled(params != null && params.size() > 0);
                            getStartButton().setEnabled(params != null && params.size() > 0);
                            getShouldRemoveCookieCheckBox()
                                    .setEnabled(
                                            HtmlParameter.Type.cookie
                                                    .name()
                                                    .equals(paramType.getSelectedItem()));
                            getRemoveCookiesLabel()
                                    .setEnabled(
                                            HtmlParameter.Type.cookie
                                                    .name()
                                                    .equals(paramType.getSelectedItem()));
                        }
                    });
        }
        return paramType;
    }

    private JComboBox<String> getParamName() {
        if (paramName == null) {
            paramName = new JComboBox<>();
        }
        return paramName;
    }

    private JCheckBox getShouldRemoveCookieCheckBox() {
        if (shouldRemoveCookieCheckBox == null) {
            shouldRemoveCookieCheckBox = new JCheckBox();
        }
        return shouldRemoveCookieCheckBox;
    }

    private JLabel getRemoveCookiesLabel() {
        if (removeCookiesLabel == null) {
            removeCookiesLabel =
                    new JLabel(messages.getString("tokengen.generate.label.remove.cookies"));
        }
        return removeCookiesLabel;
    }

    public void setExtension(ExtensionTokenGen extension) {
        this.extension = extension;
    }
}
