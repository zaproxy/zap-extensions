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
package org.zaproxy.addon.paramdigger.gui;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.paramdigger.ExtensionParamDigger;
import org.zaproxy.addon.paramdigger.ParamDiggerConfig;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ParamDiggerDialog extends StandardFieldsDialog {
    private enum Methods {
        GET(Constant.messages.getString("paramdigger.dialog.urlguess.methods.get")),
        POST(Constant.messages.getString("paramdigger.dialog.urlguess.methods.post")),
        XML(Constant.messages.getString("paramdigger.dialog.urlguess.methods.xml")),
        JSON(Constant.messages.getString("paramdigger.dialog.urlguess.methods.json"));

        private final String label;

        @Override
        public String toString() {
            return label;
        }

        private Methods(String label) {
            this.label = label;
        }
    }

    private static final long serialVersionUID = 1L;
    // Base Tab Options
    private static final String URL = "paramdigger.dialog.url";
    private static final String CONTEXT = "paramdigger.dialog.context";

    private static final String URL_GUESS = "paramdigger.dialog.urlguess";
    private static final String HEADER_GUESS = "paramdigger.dialog.headerguess";
    private static final String COOKIE_GUESS = "paramdigger.dialog.cookieguess";

    private static final String THREADPOOL_SIZE = "paramdigger.dialog.threadpool.size";

    private static final String CONTROL_TAB_KEY = "paramdigger.dialog.tab.control";
    private static final String URLGUESS_TAB_KEY = "paramdigger.dialog.tab.urlguess";
    private static final String HEADERGUESS_TAB_KEY = "paramdigger.dialog.tab.headerguess";
    private static final String COOKIEGUESS_TAB_KEY = "paramdigger.dialog.tab.cookieguess";

    private static final String[] tabLabels = {
        CONTROL_TAB_KEY, URLGUESS_TAB_KEY, HEADERGUESS_TAB_KEY, COOKIEGUESS_TAB_KEY,
    };
    private static final String PREDEF = "paramdigger.dialog.wordlist.predefined";
    private static final String CUSTOM = "paramdigger.dialog.wordlist.custom";
    private static final String BOTH = "paramdigger.dialog.wordlist.both";

    private static final String PREDEFI18N_STRING = Constant.messages.getString(PREDEF);
    private static final String CUSTOMI18N_STRING = Constant.messages.getString(CUSTOM);
    private static final String BOTHI18N_STRING = Constant.messages.getString(BOTH);

    private static final String[] wordlistLabels = {
        PREDEFI18N_STRING, CUSTOMI18N_STRING, BOTHI18N_STRING,
    };
    // Tab indices
    private static final int CONTROL_TAB = 0;
    private static final int URL_GUESS_TAB = 1;
    private static final int HEADER_GUESS_TAB = 2;
    private static final int COOKIE_GUESS_TAB = 3;

    private static final String URL_CHUNK_SIZE = "paramdigger.dialog.urlguess.chunksize";
    private static final String FCBZ_CACHE_BUSTER = "paramdigger.dialog.fcbz.cache.buster";

    private static final String URLGUESS_WORDLIST = "paramdigger.dialog.urlguess.wordlist";
    private static final String URL_FILE_LOCATON =
            "paramdigger.dialog.urlguess.wordlist.custom.file.location";
    private static final String URL_METHODS = "paramdigger.dialog.urlguess.methods";

    private static final String HEADERGUESS_WORDLIST = "paramdigger.dialog.headerguess.wordlist";
    private static final String HEADER_FILE_LOCATON =
            "paramdigger.dialog.headerguess.wordlist.custom.file.location";

    private static final String COOKIEGUESS_WORDLIST = "paramdigger.dialog.cookieguess.wordlist";
    private static final String COOKIE_FILE_LOCATON =
            "paramdigger.dialog.cookieguess.wordlist.custom.file.location";

    private static final String SKIP_BORING_HEADERS = "paramdigger.dialog.skip.boring.headers";

    private static final String WORDLIST_EMPTY = "paramdigger.dialog.error.wordlist.empty";
    private static final String WORDLIST_NOTFOUND = "paramdigger.dialog.error.wordlist.notfound";

    private static final Logger logger = LogManager.getLogger(ParamDiggerDialog.class);

    private ExtensionParamDigger extension;
    private HttpMessage target;
    private ParamDiggerConfig config;
    private Map<String, JPanel> panelMap;
    private Map<String, ZapTextField> textFieldMap;
    private Map<String, JList<Methods>> listMap;

    private JPanel getPanel(String fieldName) {
        return this.panelMap.get(fieldName);
    }

    private ZapTextField getTextField(String fieldName) {
        return this.textFieldMap.get(fieldName);
    }

    private JPanel createCustomPanel(JComponent label, JComponent field) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.add(
                label,
                LayoutHelper.getGBC(
                        0,
                        this.panelMap.size(),
                        1,
                        0.0D,
                        0.0D,
                        GridBagConstraints.BOTH,
                        new Insets(4, 4, 4, 4)));
        panel.add(
                field,
                LayoutHelper.getGBC(
                        1,
                        this.panelMap.size(),
                        1,
                        1.0D,
                        0.0D,
                        GridBagConstraints.BOTH,
                        new Insets(4, 4, 4, 4)));
        return panel;
    }

    public ParamDiggerDialog(ExtensionParamDigger extension, Frame owner, Dimension dim) {
        super(owner, "paramdigger.panel.title", dim, tabLabels);
        this.extension = extension;
    }

    public void init(HttpMessage target) {
        if (target != null) {
            this.target = target;
        }
        logger.debug("init {}", this.target);
        config = new ParamDiggerConfig();
        // TODO Add a reset button
        this.panelMap = new HashMap<>();
        this.textFieldMap = new HashMap<>();
        this.listMap = new HashMap<>();

        this.removeAllFields();
        this.setTabsVisible(
                new String[] {URLGUESS_TAB_KEY, HEADERGUESS_TAB_KEY, COOKIEGUESS_TAB_KEY}, false);

        this.addUriSelectField(CONTROL_TAB, URL, this.target);
        // TODO add context selection
        this.addComboField(CONTROL_TAB, CONTEXT, new String[] {}, "");

        this.addCheckBoxField(CONTROL_TAB, URL_GUESS, true);
        this.addCheckBoxField(URL_GUESS_TAB, FCBZ_CACHE_BUSTER, false);

        this.addComboField(
                URL_GUESS_TAB,
                URLGUESS_WORDLIST,
                wordlistLabels,
                Constant.messages.getString(PREDEF));
        // TODO maybe remove when miner arrives ?
        this.setTabsVisible(new String[] {URLGUESS_TAB_KEY}, true);

        this.addWordlistSelectField(URL_GUESS_TAB, URL_FILE_LOCATON, "", false);

        this.addNumberField(URL_GUESS_TAB, URL_CHUNK_SIZE, 2, 40, 2);

        List<Methods> urlGuessMethods = new ArrayList<>();
        urlGuessMethods.add(Methods.GET);
        urlGuessMethods.add(Methods.POST);
        // urlGuessMethods.add(Methods.XML);
        // TODO add XML text Field and json text Field (Along with vanishing effect)
        urlGuessMethods.add(Methods.JSON);
        this.addMethodPanel(URL_GUESS_TAB, URL_METHODS, urlGuessMethods, true);
        this.listMap.get(URL_METHODS).setSelectedIndex(0);

        this.addFieldListener(
                URL_GUESS,
                e -> {
                    this.setTabsVisible(
                            new String[] {URLGUESS_TAB_KEY},
                            ((JCheckBox) e.getSource()).isSelected());
                });
        this.addFieldListener(
                URLGUESS_WORDLIST,
                e -> {
                    String selected = (String) ((JComboBox) e.getSource()).getSelectedItem();
                    if (selected.equals(Constant.messages.getString(CUSTOM))
                            || selected.equals(Constant.messages.getString(BOTH))) {
                        this.getPanel(URL_FILE_LOCATON).setVisible(true);

                    } else {
                        this.getPanel(URL_FILE_LOCATON).setVisible(false);
                        this.getTextField(URL_FILE_LOCATON).setText("");
                    }
                });

        this.addCheckBoxField(CONTROL_TAB, HEADER_GUESS, false);
        this.addCheckBoxField(HEADER_GUESS_TAB, SKIP_BORING_HEADERS, false);
        this.addComboField(
                HEADER_GUESS_TAB,
                HEADERGUESS_WORDLIST,
                wordlistLabels,
                Constant.messages.getString(PREDEF));

        this.addWordlistSelectField(HEADER_GUESS_TAB, HEADER_FILE_LOCATON, "", false);

        this.addFieldListener(
                HEADER_GUESS,
                e -> {
                    this.setTabsVisible(
                            new String[] {HEADERGUESS_TAB_KEY},
                            (((JCheckBox) e.getSource()).isSelected()));
                });
        this.addFieldListener(
                HEADERGUESS_WORDLIST,
                e -> {
                    String selected = (String) ((JComboBox) e.getSource()).getSelectedItem();
                    if (selected.equals(Constant.messages.getString(CUSTOM))
                            || selected.equals(Constant.messages.getString(BOTH))) {
                        this.getPanel(HEADER_FILE_LOCATON).setVisible(true);
                    } else {
                        this.getPanel(HEADER_FILE_LOCATON).setVisible(false);
                        this.getTextField(HEADER_FILE_LOCATON).setText("");
                    }
                });

        this.addCheckBoxField(CONTROL_TAB, COOKIE_GUESS, false);
        this.addComboField(
                COOKIE_GUESS_TAB,
                COOKIEGUESS_WORDLIST,
                wordlistLabels,
                Constant.messages.getString(PREDEF));

        this.addWordlistSelectField(COOKIE_GUESS_TAB, COOKIE_FILE_LOCATON, "", false);
        this.addFieldListener(
                COOKIE_GUESS,
                e -> {
                    this.setTabsVisible(
                            new String[] {COOKIEGUESS_TAB_KEY},
                            (((JCheckBox) e.getSource()).isSelected()));
                });
        this.addFieldListener(
                COOKIEGUESS_WORDLIST,
                e -> {
                    String selected = (String) ((JComboBox) e.getSource()).getSelectedItem();
                    if (selected.equals(Constant.messages.getString(CUSTOM))
                            || selected.equals(Constant.messages.getString(BOTH))) {
                        this.getPanel(COOKIE_FILE_LOCATON).setVisible(true);
                    } else {
                        this.getPanel(COOKIE_FILE_LOCATON).setVisible(false);
                        this.getTextField(COOKIE_FILE_LOCATON).setText("");
                    }
                });
        this.addNumberField(CONTROL_TAB, THREADPOOL_SIZE, 6, 12, 8);
        this.addPadding(CONTROL_TAB);
        this.addPadding(URL_GUESS_TAB);
        this.addPadding(HEADER_GUESS_TAB);
        this.addPadding(COOKIE_GUESS_TAB);
        this.pack();
    }

    @Override
    public String getHelpIndex() {
        return "paramdigger.dialog";
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("paramdigger.dialog.button.scan");
    }

    private void addMethodPanel(
            int tabIndex, String fieldLabel, List<Methods> methods, boolean isVisible) {
        JLabel label = new JLabel(Constant.messages.getString(fieldLabel));
        label.setVerticalAlignment(JLabel.TOP);
        JList<Methods> list = new JList<>(methods.toArray(new Methods[0]));
        list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
        list.setVisibleRowCount(1);
        list.setToolTipText(
                Constant.messages.getString("paramdigger.dialog.urlguess.methods.tooltip"));
        JPanel panel = createCustomPanel(label, list);
        panel.setVisible(isVisible);
        this.addCustomComponent(tabIndex, panel);
        this.panelMap.put(fieldLabel, panel);
        this.listMap.put(fieldLabel, list);
    }

    private void addWordlistSelectField(
            int tabIndex, String fieldLabel, String filePath, boolean isVisible) {
        ZapTextField text = new ZapTextField();
        text.setText(filePath);
        JButton browseButton = new JButton("browse");
        JFileChooser fileChooser = new JFileChooser();
        browseButton.addActionListener(
                e -> {
                    if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                        text.setText(fileChooser.getSelectedFile().getAbsolutePath());
                    }
                });

        JPanel panel = new JPanel(new GridBagLayout());
        panel.add(
                new JLabel(Constant.messages.getString(fieldLabel)),
                LayoutHelper.getGBC(
                        0, 0, 1, 0.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                text,
                LayoutHelper.getGBC(
                        1, 0, 1, 1.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                browseButton,
                LayoutHelper.getGBC(
                        2, 0, 1, 0.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.setVisible(isVisible);
        this.addCustomComponent(tabIndex, panel);
        this.panelMap.put(fieldLabel, panel);
        this.textFieldMap.put(fieldLabel, text);
    }

    private void addUriSelectField(int tabIndex, String fieldLabel, HttpMessage value) {
        ZapTextField text = new ZapTextField();
        if (value != null) {
            text.setText(value.getRequestHeader().getURI().toString());
        }

        JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
        selectButton.setIcon(
                new ImageIcon(View.class.getResource("/resource/icon/16/094.png"))); // Globe icon
        selectButton.addActionListener(
                e -> {
                    NodeSelectDialog nsd = new NodeSelectDialog(ParamDiggerDialog.this);
                    SiteNode node;
                    if (value != null) {
                        node = nsd.showDialog(value.getHistoryRef().getURI());
                    } else {
                        node = nsd.showDialog((SiteNode) null);
                    }
                    if (node != null) {
                        text.setText(node.getHistoryReference().getURI().toString());
                    }
                });
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.add(
                text,
                LayoutHelper.getGBC(
                        0, 0, 1, 1.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                selectButton,
                LayoutHelper.getGBC(
                        1, 0, 1, 0.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));

        this.addCustomComponent(tabIndex, fieldLabel, panel);
        this.panelMap.put(fieldLabel, panel);
        this.textFieldMap.put(fieldLabel, text);
    }

    private void setUrlGuessMethods(ParamDiggerConfig conf) {
        for (Methods e : this.listMap.get(URL_METHODS).getSelectedValuesList()) {
            switch (e) {
                case GET:
                    conf.setUrlGetRequest(true);
                    break;
                case POST:
                    conf.setUrlPostRequest(true);
                    break;
                case JSON:
                    conf.setUrlJsonRequest(true);
                    break;
                case XML:
                    conf.setUrlXmlRequest(true);
                    break;
            }
        }
    }

    private void setWordlistsSettings(ParamDiggerConfig config, String fieldLabel, int tabIndex) {
        String choice = this.getStringValue(fieldLabel);
        switch (tabIndex) {
            case URL_GUESS_TAB:
                if (choice.equalsIgnoreCase(PREDEFI18N_STRING)) {
                    config.setUsePredefinedUrlWordlists(true);
                    config.setUseCustomUrlWordlists(false);
                } else if (choice.equalsIgnoreCase(CUSTOMI18N_STRING)) {
                    config.setUsePredefinedUrlWordlists(false);
                    config.setUseCustomUrlWordlists(true);
                    config.setCustomUrlWordlistPath(this.getTextField(URL_FILE_LOCATON).getText());
                } else {
                    config.setUsePredefinedUrlWordlists(true);
                    config.setUseCustomUrlWordlists(true);
                    config.setCustomUrlWordlistPath(this.getTextField(URL_FILE_LOCATON).getText());
                }
                break;
            case HEADER_GUESS_TAB:
                if (choice.equalsIgnoreCase(PREDEFI18N_STRING)) {
                    config.setUsePredefinedHeaderWordlists(true);
                    config.setUseCustomHeaderWordlists(false);
                } else if (choice.equalsIgnoreCase(CUSTOMI18N_STRING)) {
                    config.setUsePredefinedHeaderWordlists(false);
                    config.setUseCustomHeaderWordlists(true);
                    config.setCustomHeaderWordlistPath(
                            this.getTextField(HEADER_FILE_LOCATON).getText());
                } else {
                    config.setUsePredefinedHeaderWordlists(true);
                    config.setUseCustomHeaderWordlists(true);
                    config.setCustomHeaderWordlistPath(
                            this.getTextField(HEADER_FILE_LOCATON).getText());
                }
                break;
            case COOKIE_GUESS_TAB:
                if (choice.equalsIgnoreCase(PREDEFI18N_STRING)) {
                    config.setUsePredefinedCookieWordlists(true);
                    config.setUseCustomCookieWordlists(false);
                } else if (choice.equalsIgnoreCase(CUSTOMI18N_STRING)) {
                    config.setUsePredefinedCookieWordlists(false);
                    config.setUseCustomCookieWordlists(true);
                    config.setCustomCookieWordlistPath(
                            this.getTextField(COOKIE_FILE_LOCATON).getText());
                } else {
                    config.setUsePredefinedCookieWordlists(true);
                    config.setUseCustomCookieWordlists(true);
                    config.setCustomCookieWordlistPath(
                            this.getTextField(COOKIE_FILE_LOCATON).getText());
                }
                break;
            default:
                break;
        }
    }

    @Override
    public void save() {
        config.setUrl(this.getTextField(URL).getText());
        config.setDoUrlGuess(this.getBoolValue(URL_GUESS));
        config.setDoHeaderGuess(this.getBoolValue(HEADER_GUESS));
        config.setDoCookieGuess(this.getBoolValue(COOKIE_GUESS));

        config.setAddFcbzCacheBuster(this.getBoolValue(FCBZ_CACHE_BUSTER));
        config.setUrlGuessChunkSize(this.getIntValue(URL_CHUNK_SIZE));

        this.setWordlistsSettings(config, URLGUESS_WORDLIST, URL_GUESS_TAB);
        this.setWordlistsSettings(config, HEADERGUESS_WORDLIST, HEADER_GUESS_TAB);
        this.setWordlistsSettings(config, COOKIEGUESS_WORDLIST, COOKIE_GUESS_TAB);
        setUrlGuessMethods(config);
        config.setSkipBoringHeaders(this.getBoolValue(SKIP_BORING_HEADERS));
        config.setThreadCount(this.getIntValue(THREADPOOL_SIZE));
        config.setContext(this.getStringValue(CONTEXT));

        if (config.doUrlGuess() || config.doHeaderGuess() || config.doCookieGuess()) {
            extension.startScan(config);
        }
    }

    @Override
    public String validateFields() {
        String url = this.getTextField(URL).getText();
        if (url == null || url.isEmpty()) {
            return Constant.messages.getString("paramdigger.dialog.error.url.empty");
        }
        try {
            new URI(url, true);
            new URL(url);
        } catch (Exception e) {
            return Constant.messages.getString("paramdigger.dialog.error.url.invalid");
        }
        String urlChoice = this.getStringValue(URLGUESS_WORDLIST);
        if (urlChoice.equals(CUSTOMI18N_STRING) || urlChoice.equals(BOTHI18N_STRING)) {
            String urlWordlist = this.getTextField(URL_FILE_LOCATON).getText();
            if (urlWordlist == null || urlWordlist.isEmpty()) {
                this.requestTabFocus(URL_GUESS_TAB);
                this.getTextField(URL_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(URLGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_EMPTY);
            }
            if (!Files.isRegularFile(Paths.get(urlWordlist))) {
                this.requestTabFocus(URL_GUESS_TAB);
                this.getTextField(URL_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(URLGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_NOTFOUND);
            }
        }
        String headerChoice = this.getStringValue(HEADERGUESS_WORDLIST);
        if (headerChoice.equals(CUSTOMI18N_STRING) || headerChoice.equals(BOTHI18N_STRING)) {
            String headerWordlist = this.getTextField(HEADER_FILE_LOCATON).getText();
            if (headerWordlist == null || headerWordlist.isEmpty()) {
                this.requestTabFocus(HEADER_GUESS_TAB);
                this.getTextField(HEADER_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(HEADERGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_EMPTY);
            }
            if (!Files.isRegularFile(Paths.get(headerWordlist))) {
                this.requestTabFocus(HEADER_GUESS_TAB);
                this.getTextField(HEADER_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(HEADERGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_NOTFOUND);
            }
        }
        String cookieChoice = this.getStringValue(COOKIEGUESS_WORDLIST);
        if (cookieChoice.equals(CUSTOMI18N_STRING) || cookieChoice.equals(BOTHI18N_STRING)) {
            String cookieWordlist = this.getTextField(COOKIE_FILE_LOCATON).getText();
            if (cookieWordlist == null || cookieWordlist.isEmpty()) {
                this.requestTabFocus(COOKIE_GUESS_TAB);
                this.getTextField(COOKIE_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(COOKIEGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_EMPTY);
            }
            if (!Files.isRegularFile(Paths.get(cookieWordlist))) {
                this.requestTabFocus(COOKIE_GUESS_TAB);
                this.getTextField(COOKIE_FILE_LOCATON).requestFocusInWindow();
                return Constant.messages.getString(COOKIEGUESS_TAB_KEY)
                        + ": "
                        + Constant.messages.getString(WORDLIST_NOTFOUND);
            }
        }

        if (!(this.getBoolValue(URL_GUESS)
                || this.getBoolValue(HEADER_GUESS)
                || this.getBoolValue(COOKIE_GUESS))) {
            return Constant.messages.getString("paramdigger.dialog.error.no.guess");
        }

        return null;
    }
}
