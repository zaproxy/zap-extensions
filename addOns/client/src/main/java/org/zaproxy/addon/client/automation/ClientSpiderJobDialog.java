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
package org.zaproxy.addon.client.automation;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JTextField;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.automation.ClientSpiderJob.Parameters;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ClientSpiderJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "client.automation.dialog.tab.params", "client.automation.dialog.spider.tab.adv"
    };

    private static final String TITLE = "client.automation.dialog.spider.title";
    private static final String NAME_PARAM = "client.automation.dialog.spider.name";
    private static final String CONTEXT_PARAM = "client.automation.dialog.spider.context";
    private static final String USER_PARAM = "client.automation.dialog.spider.user";
    private static final String URL_PARAM = "client.automation.dialog.spider.url";
    private static final String MAX_DURATION_PARAM = "client.automation.dialog.spider.maxduration";
    private static final String MAX_CRAWL_DEPTH_PARAM =
            "client.automation.dialog.spider.maxcrawldepth";
    private static final String NUM_BROWSERS_PARAM = "client.automation.dialog.spider.numbrowsers";
    private static final String BROWSER_ID_PARAM = "client.automation.dialog.spider.browserid";
    private static final String FIELD_ADVANCED = "client.automation.dialog.spider.advanced";

    private static final String MAX_CHILDREN_PARAM = "client.automation.dialog.spider.maxchildren";
    private static final String INITIAL_PAGE_LOADTIME_PARAM =
            "client.automation.dialog.spider.initialtime";
    private static final String PAGE_LOADTIME_PARAM = "client.automation.dialog.spider.loadtime";
    private static final String SHUTDOWN_TIME_PARAM =
            "client.automation.dialog.spider.shutdowntime";

    private ClientSpiderJob job;
    private ExtensionSelenium extSel = null;

    public ClientSpiderJobDialog(ClientSpiderJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(450, 350),
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
        this.addComboField(0, BROWSER_ID_PARAM, browserNames, defaultBrowser);

        this.addCheckBoxField(0, FIELD_ADVANCED, advOptionsSet());
        this.addFieldListener(FIELD_ADVANCED, e -> setAdvancedTabs(getBoolValue(FIELD_ADVANCED)));

        this.addPadding(0);

        this.addNumberField(
                1,
                NUM_BROWSERS_PARAM,
                1,
                Integer.MAX_VALUE,
                getInt(
                        this.job.getParameters().getNumberOfBrowsers(),
                        Constants.getDefaultThreadCount() / 2));

        this.addNumberField(
                1,
                MAX_CRAWL_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(
                        this.job.getParameters().getMaxCrawlDepth(),
                        ClientOptions.DEFAULT_MAX_DEPTH));

        this.addNumberField(
                1,
                MAX_CHILDREN_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(this.job.getParameters().getMaxChildren(), 0));
        this.addNumberField(
                1,
                INITIAL_PAGE_LOADTIME_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(
                        this.job.getParameters().getInitialLoadTime(),
                        ClientOptions.DEFAULT_INITIAL_LOAD_TIME));
        this.addNumberField(
                1,
                PAGE_LOADTIME_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(
                        this.job.getParameters().getPageLoadTime(),
                        ClientOptions.DEFAULT_PAGE_LOAD_TIME));
        this.addNumberField(
                1,
                SHUTDOWN_TIME_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(
                        this.job.getParameters().getShutdownTime(),
                        ClientOptions.DEFAULT_SHUTDOWN_TIME));
        this.addNumberField(
                1,
                MAX_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                getInt(this.job.getParameters().getMaxDuration(), 0));

        this.addPadding(1);

        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
    }

    private int getInt(Integer i, int defaultValue) {
        if (i == null) {
            return defaultValue;
        }
        return i.intValue();
    }

    private boolean advOptionsSet() {
        Parameters params = this.job.getParameters();
        return params.getBrowserId() != null
                || params.getMaxCrawlDepth() != null
                || params.getMaxChildren() != null
                || params.getInitialLoadTime() != null
                || params.getPageLoadTime() != null
                || params.getShutdownTime() != null
                || params.getMaxDuration() != null;
    }

    private void setAdvancedTabs(boolean visible) {
        // Show/hide all except from the first tab
        this.setTabsVisible(new String[] {"client.automation.dialog.spider.tab.adv"}, visible);
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

        if (this.getBoolValue(FIELD_ADVANCED)) {
            this.job.getParameters().setNumberOfBrowsers(this.getIntValue(NUM_BROWSERS_PARAM));
            this.job.getParameters().setMaxCrawlDepth(this.getIntValue(MAX_CRAWL_DEPTH_PARAM));
            this.job.getParameters().setMaxChildren(this.getIntValue(MAX_CHILDREN_PARAM));
            this.job
                    .getParameters()
                    .setInitialLoadTime(this.getIntValue(INITIAL_PAGE_LOADTIME_PARAM));
            this.job.getParameters().setPageLoadTime(this.getIntValue(PAGE_LOADTIME_PARAM));
            this.job.getParameters().setShutdownTime(this.getIntValue(SHUTDOWN_TIME_PARAM));
            this.job.getParameters().setMaxDuration(this.getIntValue(MAX_DURATION_PARAM));
        } else {
            this.job.getParameters().setNumberOfBrowsers(null);
            this.job.getParameters().setMaxCrawlDepth(null);
            this.job.getParameters().setMaxChildren(null);
            this.job.getParameters().setInitialLoadTime(null);
            this.job.getParameters().setPageLoadTime(null);
            this.job.getParameters().setShutdownTime(null);
            this.job.getParameters().setMaxDuration(null);
        }
        this.job.setChanged();
    }

    @Override
    public String validateFields() {
        return null;
    }
}
