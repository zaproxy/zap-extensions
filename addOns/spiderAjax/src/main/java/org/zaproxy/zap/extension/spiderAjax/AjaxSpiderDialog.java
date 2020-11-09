/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JComboBox;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class AjaxSpiderDialog extends StandardFieldsDialog {

    protected static final String[] LABELS = {
        "spiderajax.scandialog.tab.scope", "spiderajax.scandialog.tab.options",
        /*"spiderajax.scandialog.tab.elements"*/ };

    private static final String FIELD_START = "spiderajax.scandialog.label.start";
    private static final String FIELD_CONTEXT = "spiderajax.scandialog.label.context";
    private static final String FIELD_USER = "spiderajax.scandialog.label.user";
    private static final String FIELD_IN_SCOPE = "spiderajax.scandialog.label.inscope";
    private static final String FIELD_SUBTREE_ONLY =
            "spiderajax.scandialog.label.spiderSubtreeOnly";
    private static final String FIELD_BROWSER = "spiderajax.scandialog.label.browser";
    private static final String FIELD_ADVANCED = "spiderajax.scandialog.label.adv";

    private static final String FIELD_NUM_BROWSERS = "spiderajax.options.label.browsers";

    private static final String FIELD_DEPTH = "spiderajax.options.label.depth";
    private static final String FIELD_CRAWL_STATES = "spiderajax.options.label.crawlstates";
    private static final String FIELD_DURATION = "spiderajax.options.label.maxduration";
    private static final String FIELD_EVENT_WAIT = "spiderajax.options.label.eventwait";
    private static final String FIELD_RELOAD_WAIT = "spiderajax.options.label.reloadwait";

    private static final Logger logger = Logger.getLogger(AjaxSpiderDialog.class);
    private static final long serialVersionUID = 1L;

    private ExtensionAjax extension = null;
    private ExtensionSelenium extSel = null;

    private JButton[] extraButtons;

    private Target target;
    private AjaxSpiderParam params = null;
    // private OptionsAjaxSpiderTableModel ajaxSpiderClickModel = null;
    private AllowedResourcesTableModel allowedResourcesTableModel;

    /**
     * Flag that holds the previous checked state of the "Subtree Only" checkbox.
     *
     * <p>Used to restore the previous checked state between dialogue invocations.
     *
     * @see #FIELD_SUBTREE_ONLY
     */
    private boolean subtreeOnlyPreviousCheckedState;

    private final ExtensionUserManagement extUserMgmt;

    public AjaxSpiderDialog(ExtensionAjax ext, Frame owner, Dimension dim) {
        super(owner, "spiderajax.scandialog.title", dim, LABELS);

        this.allowedResourcesTableModel = new AllowedResourcesTableModel();
        this.extension = ext;
        this.extUserMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
    }

    public void init(Target target) {
        if (target != null) {
            // If one isnt specified then leave the previously selected one
            this.target = target;
        }

        logger.debug("init " + this.target);
        if (params == null) {
            params = this.extension.getAjaxSpiderParam();
        }

        this.removeAllFields();

        this.addTargetSelectField(0, FIELD_START, this.target, true, false);
        this.addComboField(0, FIELD_CONTEXT, new String[] {}, "");
        this.addComboField(0, FIELD_USER, new String[] {}, "");
        this.addCheckBoxField(0, FIELD_IN_SCOPE, false);
        this.addCheckBoxField(0, FIELD_SUBTREE_ONLY, subtreeOnlyPreviousCheckedState);
        this.addFieldListener(
                FIELD_IN_SCOPE,
                new ActionListener() {

                    @Override
                    public void actionPerformed(ActionEvent e) {
                        boolean selected = getBoolValue(FIELD_IN_SCOPE);

                        getField(FIELD_CONTEXT)
                                .setEnabled(
                                        !selected
                                                && ((JComboBox<?>) getField(FIELD_CONTEXT))
                                                                .getItemCount()
                                                        > 1);
                        getField(FIELD_USER)
                                .setEnabled(
                                        !selected
                                                && ((JComboBox<?>) getField(FIELD_USER))
                                                                .getItemCount()
                                                        > 1);
                    }
                });

        List<ProvidedBrowserUI> browserList = getExtSelenium().getProvidedBrowserUIList();
        List<String> browserNames = new ArrayList<String>();
        String defaultBrowser = null;
        for (ProvidedBrowserUI browser : browserList) {
            browserNames.add(browser.getName());
            if (browser.getBrowser().getId().equals(params.getBrowserId())) {
                defaultBrowser = browser.getName();
            }
        }

        this.addComboField(0, FIELD_BROWSER, browserNames, defaultBrowser);

        // This option is always read from the 'global' options
        this.addCheckBoxField(0, FIELD_ADVANCED, params.isShowAdvancedDialog());

        this.addPadding(0);

        this.addFieldListener(
                FIELD_CONTEXT,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setUsers();
                    }
                });

        this.addFieldListener(
                FIELD_ADVANCED,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // Save the adv option permanently for next time

                        setAdvancedOptions(getBoolValue(FIELD_ADVANCED));
                    }
                });

        if (target != null) {
            this.targetSelected(FIELD_START, this.target);
            this.setUsers();
        } else {
            getField(FIELD_CONTEXT).setEnabled(false);
            getField(FIELD_USER).setEnabled(false);
        }

        this.setAdvancedOptions(params.isShowAdvancedDialog());

        // Options tab
        this.addNumberField(
                1, FIELD_NUM_BROWSERS, 1, Integer.MAX_VALUE, params.getNumberOfBrowsers());
        this.addNumberField(1, FIELD_DEPTH, 0, Integer.MAX_VALUE, params.getMaxCrawlDepth());
        this.addNumberField(
                1, FIELD_CRAWL_STATES, 0, Integer.MAX_VALUE, params.getMaxCrawlStates());
        this.addNumberField(1, FIELD_DURATION, 0, Integer.MAX_VALUE, params.getMaxDuration());
        this.addNumberField(1, FIELD_EVENT_WAIT, 1, Integer.MAX_VALUE, params.getEventWait());
        this.addNumberField(1, FIELD_RELOAD_WAIT, 1, Integer.MAX_VALUE, params.getReloadWait());

        allowedResourcesTableModel.setAllowedResources(params.getAllowedResources());
        AllowedResourcesPanel allowedResourcesPanel =
                new AllowedResourcesPanel(this, allowedResourcesTableModel);
        allowedResourcesPanel.setRemoveWithoutConfirmation(
                !params.isConfirmRemoveAllowedResource());
        addCustomComponent(1, allowedResourcesPanel);

        this.addPadding(1);

        /* Need to check this really works before releasing it
        getAjaxSpiderClickModel().setElems(params.getElems());
        this.setCustomTabPanel(2, new AjaxSpiderMultipleOptionsPanel(getAjaxSpiderClickModel()));
        */

        this.pack();
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

    /*
    private OptionsAjaxSpiderTableModel getAjaxSpiderClickModel() {
    	if (ajaxSpiderClickModel == null) {
    		ajaxSpiderClickModel = new OptionsAjaxSpiderTableModel();
    	}
    	return ajaxSpiderClickModel;
    }
    */

    @Override
    public String getHelpIndex() {
        return "addon.spiderajax.dialog";
    }

    private void setAdvancedOptions(boolean adv) {
        this.setTabsVisible(
                new String[] {
                    "spiderajax.scandialog.tab.options",
                    /*"spiderajax.scandialog.tab.elements"*/
                },
                adv);
        // Always save in the 'global' options
        extension.getAjaxSpiderParam().setShowAdvancedDialog(adv);
    }

    @Override
    public void targetSelected(String field, Target target) {
        boolean contextSelected = false;
        List<String> ctxNames = new ArrayList<String>();
        if (target != null) {
            this.target = target;
            if (target.getStartNode() != null) {
                Session session = Model.getSingleton().getSession();
                List<Context> contexts = session.getContextsForNode(target.getStartNode());
                ctxNames.add("");
                for (Context context : contexts) {
                    ctxNames.add(context.getName());
                }

            } else if (target.getContext() != null) {
                ctxNames.add(target.getContext().getName());
                contextSelected = true;
            }
        }
        this.setComboFields(FIELD_CONTEXT, ctxNames, "");
        this.getField(FIELD_CONTEXT).setEnabled(ctxNames.size() > 1);
        this.getField(FIELD_IN_SCOPE).setEnabled(!contextSelected);
    }

    private Context getSelectedContext() {
        String ctxName = this.getStringValue(FIELD_CONTEXT);
        if (this.extUserMgmt != null && !this.isEmptyField(FIELD_CONTEXT)) {
            Session session = Model.getSingleton().getSession();
            return session.getContext(ctxName);
        }
        return null;
    }

    private User getSelectedUser() {
        Context context = this.getSelectedContext();
        if (context != null && extUserMgmt != null) {
            String userName = this.getStringValue(FIELD_USER);
            List<User> users =
                    this.extUserMgmt.getContextUserAuthManager(context.getId()).getUsers();
            for (User user : users) {
                if (userName.equals(user.getName())) {
                    return user;
                }
            }
        }
        return null;
    }

    private void setUsers() {
        boolean contextSelected = false;
        Context context = this.getSelectedContext();
        List<String> userNames = new ArrayList<>();
        if (context != null && extUserMgmt != null) {
            List<User> users = extUserMgmt.getContextUserAuthManager(context.getId()).getUsers();
            userNames.add("");
            for (User user : users) {
                userNames.add(user.getName());
            }
            contextSelected = true;
        }
        this.setComboFields(FIELD_USER, userNames, "");
        this.getField(FIELD_USER).setEnabled(userNames.size() > 1);
        this.getField(FIELD_IN_SCOPE).setEnabled(!contextSelected);
    }

    /** Resets the spider dialogue to its default state. */
    public void reset() {
        // Reset to the global options
        params = null;
        target = null;

        init(target);
        repaint();
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("spiderajax.scandialog.button.scan");
    }

    @Override
    public JButton[] getExtraButtons() {
        if (extraButtons == null) {
            JButton resetButton =
                    new JButton(Constant.messages.getString("spiderajax.scandialog.button.reset"));
            resetButton.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            reset();
                        }
                    });

            extraButtons = new JButton[] {resetButton};
        }
        return extraButtons;
    }

    /** Use the save method to launch a scan */
    @Override
    public void save() {
        AjaxSpiderParam params = this.extension.getAjaxSpiderParam().clone();

        String selectedBrowser = getSelectedBrowser();
        if (selectedBrowser != null) {
            params.setBrowserId(selectedBrowser);
        }

        if (this.getBoolValue(FIELD_ADVANCED)) {
            params.setNumberOfBrowsers(this.getIntValue(FIELD_NUM_BROWSERS));
            params.setMaxCrawlDepth(this.getIntValue(FIELD_DEPTH));
            params.setMaxCrawlStates(this.getIntValue(FIELD_CRAWL_STATES));
            params.setMaxDuration(this.getIntValue(FIELD_DURATION));
            params.setEventWait(this.getIntValue(FIELD_EVENT_WAIT));
            params.setReloadWait(this.getIntValue(FIELD_RELOAD_WAIT));
            params.setAllowedResources(allowedResourcesTableModel.getElements());

            // params.setElems(getAjaxSpiderClickModel().getElements());

        }

        URI startUri = null;
        if (!this.getStringValue(FIELD_START).equals(getTargetText(target))) {
            startUri = URI.create(getStringValue(FIELD_START));
        } else {
            SiteNode startNode = target.getStartNode();
            if (startNode != null) {
                startUri = URI.create(startNode.getHistoryReference().getURI().toString());
            } else if (target.getContext() != null) {
                startUri = extension.getFirstUriInContext(target.getContext());
            }
        }

        if (startUri == null) {
            return;
        }

        AjaxSpiderTarget.Builder targetBuilder =
                AjaxSpiderTarget.newBuilder(extension.getModel().getSession())
                        .setInScopeOnly(getBoolValue(FIELD_IN_SCOPE))
                        .setOptions(params)
                        .setStartUri(startUri)
                        .setSubtreeOnly(getBoolValue(FIELD_SUBTREE_ONLY));

        User user = getSelectedUser();
        if (user != null) {
            targetBuilder.setUser(user);
        } else {
            Context context = getSelectedContext();
            if (context == null && target != null && target.getContext() != null) {
                context = target.getContext();
            }
            targetBuilder.setContext(context);
        }

        subtreeOnlyPreviousCheckedState = getBoolValue(FIELD_SUBTREE_ONLY);

        this.extension.startScan(targetBuilder.build());
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
        if (extension.isSpiderRunning()) {
            return Constant.messages.getString("spiderajax.scandialog.alreadyrunning.error");
        }

        if (Control.Mode.safe == Control.getSingleton().getMode()) {
            // The dialogue shouldn't be shown when in safe mode but if it is warn.
            return Constant.messages.getString("spiderajax.scandialog.notSafe.error");
        }

        if (this.isEmptyField(FIELD_START)) {
            return Constant.messages.getString("spiderajax.scandialog.nostart.error");
        }

        URI startUri = null;
        Context context = getSelectedContext();
        if (!getStringValue(FIELD_START).equals(getTargetText(target))) {
            String url = this.getStringValue(FIELD_START);
            try {
                // Need both constructors as they catch slightly different issues ;)
                startUri = new URI(url);
                new URL(url);
            } catch (Exception e) {
                return Constant.messages.getString("spiderajax.scandialog.nostart.error");
            }
        } else if (this.target != null) {
            if (!this.target.isValid()) {
                return Constant.messages.getString("spiderajax.scandialog.nostart.error");
            }

            SiteNode startNode = target.getStartNode();
            if (startNode != null) {
                startUri = URI.create(startNode.getHistoryReference().getURI().toString());
            } else if (context != null) {
                if (getBoolValue(FIELD_SUBTREE_ONLY)) {
                    return Constant.messages.getString(
                            "spiderajax.scandialog.nostart.subtreeOnly.error");
                }
                startUri = extension.getFirstUriInContext(context);
            }
        }

        if (startUri == null) {
            if (context != null) {
                return Constant.messages.getString("spiderajax.scandialog.nostart.context.error");
            }
            return Constant.messages.getString("spiderajax.scandialog.nostart.error");
        }

        if (context != null && !context.isInContext(startUri.toString())) {
            return Constant.messages.getString("spiderajax.scandialog.startNotInContext.error");
        }

        if (!extension.getModel().getSession().isInScope(startUri.toString())) {
            if (Control.getSingleton().getMode() == Control.Mode.protect) {
                return Constant.messages.getString(
                        "spiderajax.scandialog.startProtectedMode.error");
            }

            if (getBoolValue(FIELD_IN_SCOPE)) {
                return Constant.messages.getString("spiderajax.scandialog.startNotInScope.error");
            }
        }

        String selectedBrowser = getSelectedBrowser();
        if (selectedBrowser == null) {
            return Constant.messages.getString("spiderajax.scandialog.nobrowser.error");
        }

        if (Browser.PHANTOM_JS.getId().equals(selectedBrowser)) {
            String host = startUri.getHost();
            if ("localhost".equalsIgnoreCase(host)
                    || "127.0.0.1".equals(host)
                    || "[::1]".equals(host)) {
                return Constant.messages.getString(
                        "spiderajax.warn.message.phantomjs.bug.invalid.target");
            }
        }

        return null;
    }
}
