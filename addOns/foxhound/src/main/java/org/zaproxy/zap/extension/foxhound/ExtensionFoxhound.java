/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound;

import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.foxhound.alerts.FoxhoundAlertHelper;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundOptions;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;
import org.zaproxy.zap.extension.foxhound.db.TaintInfoStore;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundLaunchButton;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundPanel;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundScanStatus;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

public class ExtensionFoxhound extends ExtensionAdaptor implements ExampleAlertProvider {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionFoxhound.class);

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionFoxhound";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionNetwork.class, ExtensionSelenium.class);

    private FoxhoundExportServer exportServer;
    private TaintInfoStore taintStore;
    private FoxhoundAlertHelper alertHelper;

    private FoxhoundOptions options;
    private FoxhoundSeleniumProfile seleniumProfile;
    private FoxhoundLaunchButton launchButton;
    private FoxhoundPanel foxhoundPanel;
    private FoxhoundScanStatus foxhoundScanStatus;

    public ExtensionFoxhound() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // Start the alert helper
        getAlertHelper();

        // Load Options
        FoxhoundOptions options = getOptions();
        extensionHook.addOptionsParamSet(options);

        // Automatically update options in the selenium profile if they are changed
        seleniumProfile = getSeleniumProfile();
        seleniumProfile.setOptions(options);
        options.addPropertyChangeListener(e -> seleniumProfile.writeOptionsToProfile());

        // Start the Export Server
        ExtensionNetwork extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);

        getExportServer().start(extensionNetwork, getOptions(), this.getTaintStore());

        // Load GUIs
        if (hasView()) {
            extensionHook.getHookView().addMainToolBarComponent(getLaunchButton());
            extensionHook.getHookView().addStatusPanel(getFoxhoundPanel());
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightComponent(getFoxhoundScanStatus().getCountLabel());
        }

        LOGGER.info(
                "Starting the Foxhound ZAP extension with {} sources and {} sinks.",
                FoxhoundConstants.ALL_SOURCES.size(),
                FoxhoundConstants.ALL_SINKS.size());
    }

    @Override
    public void postInit() {
        if (seleniumProfile != null) {
            seleniumProfile.writeOptionsToProfile();
        }
    }

    @Override
    public void stop() {
        LOGGER.info("Stopping the Foxhound ZAP extension");
        getExportServer().stop();
    }

    @Override
    public void unload() {
        super.unload();

        if (hasView()) {
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightComponent(getFoxhoundScanStatus().getCountLabel());
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("foxhound.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private FoxhoundOptions getOptions() {
        if (options == null) {
            options = new FoxhoundOptions();
        }
        return options;
    }

    public FoxhoundSeleniumProfile getSeleniumProfile() {
        if (seleniumProfile == null) {
            seleniumProfile = new FoxhoundSeleniumProfile();
        }
        return seleniumProfile;
    }

    private FoxhoundLaunchButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new FoxhoundLaunchButton(getSeleniumProfile());
        }
        return launchButton;
    }

    public FoxhoundExportServer getExportServer() {
        if (exportServer == null) {
            exportServer = new FoxhoundExportServer();
        }
        return exportServer;
    }

    public TaintInfoStore getTaintStore() {
        if (taintStore == null) {
            taintStore = new TaintInfoStore();
        }
        return taintStore;
    }

    public FoxhoundAlertHelper getAlertHelper() {
        if (alertHelper == null) {
            alertHelper = new FoxhoundAlertHelper(getTaintStore());
        }
        return alertHelper;
    }

    public FoxhoundPanel getFoxhoundPanel() {
        if (foxhoundPanel == null) {
            foxhoundPanel = new FoxhoundPanel(this);
        }
        return foxhoundPanel;
    }

    public FoxhoundScanStatus getFoxhoundScanStatus() {
        if (foxhoundScanStatus == null) {
            foxhoundScanStatus = new FoxhoundScanStatus();
        }
        return foxhoundScanStatus;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return FoxhoundAlertHelper.getExampleAlerts();
    }
}
