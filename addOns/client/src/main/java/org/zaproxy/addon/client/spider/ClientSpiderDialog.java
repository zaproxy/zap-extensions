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
package org.zaproxy.addon.client.spider;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.NodeSelectDialog;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ClientSpiderDialog extends StandardFieldsDialog {

    protected static final String[] LABELS = {
        "client.scandialog.tab.scope", "client.scandialog.tab.options"
    };

    private static final String FIELD_START = "client.scandialog.label.start";
    private static final String FIELD_SUBTREE_ONLY = "client.scandialog.label.spiderSubtreeOnly";
    private static final String FIELD_BROWSER = "client.scandialog.label.browser";
    private static final String FIELD_ADVANCED = "client.scandialog.label.adv";
    private static final String FIELD_NUM_BROWSERS = "client.options.label.browsers";
    private static final String FIELD_DEPTH = "client.options.label.depth";
    private static final String FIELD_CHILDREN = "client.options.label.children";
    private static final String FIELD_DURATION = "client.options.label.maxduration";
    private static final String FIELD_INITIAL_LOAD_TIME = "client.options.label.initialloadtime";
    private static final String FIELD_PAGE_LOAD_TIME = "client.options.label.pageloadtime";
    private static final String FIELD_SHUTDOWN_TIME = "client.options.label.shutdowntime";

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderDialog.class);
    private static final long serialVersionUID = 1L;

    private ExtensionClientIntegration extension = null;
    private ExtensionSelenium extSel = null;

    private JButton[] extraButtons;

    private SiteNode targetNode;
    private String targetUrl;
    private ClientOptions params = null;
    private ZapTextField urlStartField;
    private boolean subtreeOnlyPreviousCheckedState;

    public ClientSpiderDialog(ExtensionClientIntegration ext, Frame owner, Dimension dim) {
        super(owner, "client.scandialog.title", dim, LABELS);
        this.extension = ext;
        params = this.extension.getClientParam();
    }

    public void init(SiteNode node) {
        this.init(node, null);
    }

    public void init(String url) {
        this.init(null, url);
    }

    private void init(SiteNode node, String url) {
        if (node != null) {
            this.targetNode = node;
            this.targetUrl = null;
            LOGGER.debug("init {}", this.targetNode);
        } else if (url != null) {
            this.targetUrl = url;
            this.targetNode = null;
            LOGGER.debug("init {}", this.targetUrl);
        } else {
            LOGGER.debug("init (no target)");
        }

        this.removeAllFields();

        if (node != null) {
            this.addNodeSelectField(0, FIELD_START, node, true, false);
        } else {
            this.addUrlSelectField(0, FIELD_START, url, true, false);
        }

        this.addCheckBoxField(0, FIELD_SUBTREE_ONLY, subtreeOnlyPreviousCheckedState);
        this.addComboField(0, FIELD_BROWSER, new ArrayList<String>(), null);

        // This option is always read from the 'global' options
        this.addCheckBoxField(0, FIELD_ADVANCED, params.isShowAdvancedDialog());

        this.addPadding(0);

        this.addFieldListener(
                FIELD_ADVANCED,
                e ->
                        // Save the adv option permanently for next time
                        setAdvancedOptions(getBoolValue(FIELD_ADVANCED)));

        this.setAdvancedOptions(params.isShowAdvancedDialog());

        // Options tab
        this.addNumberField(1, FIELD_NUM_BROWSERS, 1, Integer.MAX_VALUE, params.getThreadCount());
        this.addNumberField(1, FIELD_DEPTH, 0, Integer.MAX_VALUE, params.getMaxDepth());
        this.addNumberField(1, FIELD_CHILDREN, 0, Integer.MAX_VALUE, params.getMaxChildren());
        this.addNumberField(
                1,
                FIELD_INITIAL_LOAD_TIME,
                0,
                Integer.MAX_VALUE,
                params.getInitialLoadTimeInSecs());
        this.addNumberField(
                1, FIELD_PAGE_LOAD_TIME, 0, Integer.MAX_VALUE, params.getPageLoadTimeInSecs());
        this.addNumberField(
                1, FIELD_SHUTDOWN_TIME, 0, Integer.MAX_VALUE, params.getShutdownTimeInSecs());
        this.addNumberField(1, FIELD_DURATION, 0, Integer.MAX_VALUE, params.getMaxDuration());

        this.addPadding(1);

        this.pack();

        this.updateBrowsers();
    }

    /* Tweaked version of super.addNodeSelectField to cope with a URL that might not be in the sites tree */
    public void addUrlSelectField(
            int tabIndex,
            final String fieldLabel,
            final String url,
            final boolean editable,
            final boolean allowRoot) {
        urlStartField = new ZapTextField();
        urlStartField.setEditable(editable);
        if (url != null) {
            urlStartField.setText(url);
        }
        JButton selectButton = new JButton(Constant.messages.getString("all.button.select"));
        selectButton.setIcon(
                new ImageIcon(View.class.getResource("/resource/icon/16/094.png"))); // Globe icon
        selectButton.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        NodeSelectDialog nsd = new NodeSelectDialog(ClientSpiderDialog.this);
                        nsd.setAllowRoot(allowRoot);
                        SiteNode node = nsd.showDialog((SiteNode) null);
                        if (node != null) {
                            urlStartField.setText(getNodeText(node));
                            siteNodeSelected(fieldLabel, node);
                        }
                    }
                });
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        panel.add(
                urlStartField,
                LayoutHelper.getGBC(
                        0, 0, 1, 1.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));
        panel.add(
                selectButton,
                LayoutHelper.getGBC(
                        1, 0, 1, 0.0D, 0.0D, GridBagConstraints.BOTH, new Insets(4, 4, 4, 4)));

        this.addCustomComponent(tabIndex, fieldLabel, panel);
    }

    /* Copied from the private super method */
    private static String getNodeText(SiteNode node) {
        if (node != null && node.getHistoryReference() != null) {
            String url = node.getHistoryReference().getURI().toString();
            if (!node.isLeaf() && url.endsWith("/")) {
                // Strip off the slash so we don't match a leaf
                // node with the same name
                url = url.substring(0, url.length() - 1);
            }
            return url;
        }
        return "";
    }

    private ExtensionSelenium getExtSelenium() {
        if (extSel == null) {
            extSel =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSelenium.class);
        }
        return extSel;
    }

    /**
     * Updates the choices available in "Browser" combo box, based on the currently available
     * browsers.
     *
     * @see ExtensionSelenium#getConfiguredBrowsers()
     */
    public void updateBrowsers() {
        List<ProvidedBrowserUI> browserList = getExtSelenium().getProvidedBrowserUIList();
        List<String> browserNames = new ArrayList<>();
        String defaultBrowser = null;
        for (ProvidedBrowserUI browser : browserList) {
            browserNames.add(browser.getName());
            if (browser.getBrowser().getId().equals(params.getBrowserId())) {
                defaultBrowser = browser.getName();
            }
        }

        setComboFields(FIELD_BROWSER, browserNames, defaultBrowser);
    }

    private void setAdvancedOptions(boolean adv) {
        this.setTabsVisible(
                new String[] {
                    "client.scandialog.tab.options",
                },
                adv);
        // Always save in the 'global' options
        extension.getClientParam().setShowAdvancedDialog(adv);
    }

    /** Resets the spider dialogue to its default state. */
    public void reset() {
        targetNode = null;
        targetUrl = null;

        init(null, null);
        repaint();
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("client.scandialog.button.scan");
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton resetButton =
                    new JButton(Constant.messages.getString("client.scandialog.button.reset"));
            resetButton.addActionListener(e -> reset());

            extraButtons = new JButton[] {resetButton};
        }
        return extraButtons;
    }

    private String getStartUrl() {
        if (this.targetNode == null) {
            return this.urlStartField.getText();
        }
        return this.getStringValue(FIELD_START);
    }

    /** Use the save method to launch a scan */
    @Override
    public void save() {
        ClientOptions params = this.extension.getClientParam();

        String selectedBrowser = getSelectedBrowser();
        if (selectedBrowser != null) {
            params.setBrowserId(selectedBrowser);
        }

        if (this.getBoolValue(FIELD_ADVANCED)) {
            params.setThreadCount(this.getIntValue(FIELD_NUM_BROWSERS));
            params.setMaxDepth(this.getIntValue(FIELD_DEPTH));
            params.setMaxChildren(this.getIntValue(FIELD_CHILDREN));
            params.setInitialLoadTimeInSecs(this.getIntValue(FIELD_INITIAL_LOAD_TIME));
            params.setPageLoadTimeInSecs(this.getIntValue(FIELD_PAGE_LOAD_TIME));
            params.setShutdownTimeInSecs(this.getIntValue(FIELD_SHUTDOWN_TIME));
            params.setMaxDuration(this.getIntValue(FIELD_DURATION));
        }

        subtreeOnlyPreviousCheckedState = getBoolValue(FIELD_SUBTREE_ONLY);

        this.extension.runSpider(getStartUrl(), params);
    }

    /**
     * Gets the selected browser.
     *
     * @return the selected browser, {@code null} if none selected
     */
    private String getSelectedBrowser() {
        if (isEmptyField(FIELD_BROWSER)) {
            return null;
        }

        String browserName = this.getStringValue(FIELD_BROWSER);
        List<ProvidedBrowserUI> browserList = getExtSelenium().getProvidedBrowserUIList();
        for (ProvidedBrowserUI bui : browserList) {
            if (browserName.equals(bui.getName())) {
                return bui.getBrowser().getId();
            }
        }
        return null;
    }

    @Override
    public String validateFields() {
        if (Control.Mode.safe == Control.getSingleton().getMode()) {
            // The dialogue shouldn't be shown when in safe mode but if it is warn.
            return Constant.messages.getString("client.scandialog.notSafe.error");
        }

        String startUrl = getStartUrl();

        if (StringUtils.isEmpty(startUrl)) {
            return Constant.messages.getString("client.scandialog.nostart.error");
        }
        try {
            // Need both constructors as they catch slightly different issues ;)
            new URI(startUrl);
            new URL(startUrl);
        } catch (Exception e) {
            return Constant.messages.getString("client.scandialog.nostart.error");
        }

        if (Control.getSingleton().getMode() == Control.Mode.protect
                && !extension.getModel().getSession().isInScope(startUrl)) {
            return Constant.messages.getString("client.scandialog.startProtectedMode.error");
        }

        return null;
    }
}
