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
package org.zaproxy.zap.extension.spiderAjax.automation;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTextField;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.spiderAjax.automation.AjaxSpiderJob.Parameters;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AjaxSpiderJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "spiderajax.automation.dialog.tab.params", "spiderajax.automation.dialog.ajaxspider.tab.adv"
    };

    private static final String TITLE = "spiderajax.automation.dialog.ajaxspider.title";
    private static final String NAME_PARAM = "spiderajax.automation.dialog.ajaxspider.name";
    private static final String CONTEXT_PARAM = "spiderajax.automation.dialog.ajaxspider.context";
    private static final String USER_PARAM = "automation.dialog.all.user";
    private static final String URL_PARAM = "spiderajax.automation.dialog.ajaxspider.url";
    private static final String MAX_DURATION_PARAM =
            "spiderajax.automation.dialog.ajaxspider.maxduration";
    private static final String MAX_CRAWL_DEPTH_PARAM =
            "spiderajax.automation.dialog.ajaxspider.maxcrawldepth";
    private static final String NUM_BROWSERS_PARAM =
            "spiderajax.automation.dialog.ajaxspider.numbrowsers";
    private static final String FIELD_ADVANCED = "spiderajax.automation.dialog.ajaxspider.advanced";

    private static final String BROWSER_ID_PARAM =
            "spiderajax.automation.dialog.ajaxspider.browserid";
    private static final String MAX_CRAWL_STATES_PARAM =
            "spiderajax.automation.dialog.ajaxspider.maxcrawlstates";
    private static final String EVENT_WAIT_PARAM =
            "spiderajax.automation.dialog.ajaxspider.eventwait";
    private static final String RELOAD_WAIT_PARAM =
            "spiderajax.automation.dialog.ajaxspider.reloadwait";
    private static final String CLICK_DEFAULT_ELEMS_PARAM =
            "spiderajax.automation.dialog.ajaxspider.clickdefaultelems";
    private static final String CLICK_ELEMS_ONCE_PARAM =
            "spiderajax.automation.dialog.ajaxspider.clickelemsonce";
    private static final String RANDOM_INPUTS_PARAM =
            "spiderajax.automation.dialog.ajaxspider.randominputs";

    private AjaxSpiderJob job;
    private ExtensionSelenium extSel = null;

    public AjaxSpiderJobDialog(AjaxSpiderJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(450, 400),
                TAB_LABELS);
        this.job = job;
        this.addTextField(0, NAME_PARAM, this.job.getName());
        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(0, CONTEXT_PARAM, contextNames, this.job.getParameters().getContext());

        List<String> users = job.getEnv().getAllUserNames();
        // Add blank option
        users.add(0, "");
        this.addComboField(0, USER_PARAM, users, this.job.getParameters().getUser());

        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(this.job.getParameters().getUrl());
        }
        this.addNumberField(
                0,
                MAX_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxDuration()));
        this.addNumberField(
                0,
                MAX_CRAWL_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxCrawlDepth()));
        this.addNumberField(
                0,
                NUM_BROWSERS_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getNumberOfBrowsers()));
        this.addCheckBoxField(0, FIELD_ADVANCED, advOptionsSet());

        this.addFieldListener(
                FIELD_ADVANCED,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
                    }
                });

        this.addPadding(0);

        List<ProvidedBrowserUI> browserList = getExtSelenium().getProvidedBrowserUIList();
        List<String> browserNames = new ArrayList<>();
        String defaultBrowser = "";
        browserNames.add(""); // Default to empty
        for (ProvidedBrowserUI browser : browserList) {
            browserNames.add(browser.getName());
            if (browser.getBrowser().getId().equals(this.job.getParameters().getBrowserId())) {
                defaultBrowser = browser.getName();
            }
        }
        this.addComboField(1, BROWSER_ID_PARAM, browserNames, defaultBrowser);

        this.addNumberField(
                1,
                MAX_CRAWL_STATES_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxCrawlStates()));
        this.addNumberField(
                1,
                EVENT_WAIT_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getEventWait()));
        this.addNumberField(
                1,
                RELOAD_WAIT_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getReloadWait()));
        this.addCheckBoxField(
                1,
                CLICK_DEFAULT_ELEMS_PARAM,
                JobUtils.unBox(this.job.getParameters().getClickDefaultElems()));
        this.addCheckBoxField(
                1,
                CLICK_ELEMS_ONCE_PARAM,
                JobUtils.unBox(this.job.getParameters().getClickElemsOnce()));
        this.addCheckBoxField(
                1, RANDOM_INPUTS_PARAM, JobUtils.unBox(this.job.getParameters().getRandomInputs()));

        this.addPadding(1);

        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
    }

    private boolean advOptionsSet() {
        Parameters params = this.job.getParameters();
        return params.getBrowserId() != null
                || params.getMaxCrawlStates() != null
                || params.getEventWait() != null
                || params.getReloadWait() != null
                || params.getClickDefaultElems() != null
                || params.getClickElemsOnce() != null
                || params.getRandomInputs() != null;
    }

    private void setAdvancedTabs(boolean visible) {
        // Show/hide all except from the first tab
        this.setTabsVisible(
                new String[] {"spiderajax.automation.dialog.ajaxspider.tab.adv"}, visible);
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

    @Override
    public void save() {
        this.job.setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setContext(this.getStringValue(CONTEXT_PARAM));
        this.job.getParameters().setUser(this.getStringValue(USER_PARAM));
        this.job.getParameters().setUrl(this.getStringValue(URL_PARAM));
        this.job.getParameters().setMaxDuration(this.getIntValue(MAX_DURATION_PARAM));
        this.job.getParameters().setMaxCrawlDepth(this.getIntValue(MAX_CRAWL_DEPTH_PARAM));
        this.job.getParameters().setNumberOfBrowsers(this.getIntValue(NUM_BROWSERS_PARAM));

        if (this.getBoolValue(FIELD_ADVANCED)) {
            String browserName = this.getStringValue(BROWSER_ID_PARAM);
            if (browserName.isEmpty()) {
                this.job.getParameters().setBrowserId(null);
            } else {
                List<ProvidedBrowserUI> browserList = getExtSelenium().getProvidedBrowserUIList();
                for (ProvidedBrowserUI bui : browserList) {
                    if (browserName.equals(bui.getName())) {
                        this.job.getParameters().setBrowserId(bui.getBrowser().getId());
                        break;
                    }
                }
            }
            this.job.getParameters().setMaxCrawlStates(this.getIntValue(MAX_CRAWL_STATES_PARAM));
            this.job.getParameters().setEventWait(this.getIntValue(EVENT_WAIT_PARAM));
            this.job.getParameters().setReloadWait(this.getIntValue(RELOAD_WAIT_PARAM));
            this.job
                    .getParameters()
                    .setClickDefaultElems(this.getBoolValue(CLICK_DEFAULT_ELEMS_PARAM));
            this.job.getParameters().setClickElemsOnce(this.getBoolValue(CLICK_ELEMS_ONCE_PARAM));
            this.job.getParameters().setRandomInputs(this.getBoolValue(RANDOM_INPUTS_PARAM));
        } else {
            this.job.getParameters().setBrowserId(null);
            this.job.getParameters().setMaxCrawlStates(null);
            this.job.getParameters().setEventWait(null);
            this.job.getParameters().setReloadWait(null);
            this.job.getParameters().setClickDefaultElems(null);
            this.job.getParameters().setClickElemsOnce(null);
            this.job.getParameters().setRandomInputs(null);
        }
    }

    @Override
    public String validateFields() {
        // TODO validate url - coping with envvars :O
        return null;
    }
}
