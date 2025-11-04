package org.zaproxy.zap.extension.foxhound;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundOptions;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundLaunchButton;
import org.zaproxy.zap.extension.foxhound.ui.FoxhoundPanel;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

import java.util.List;


public class ExtensionFoxhound extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionFoxhound.class);

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionFoxhound";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionNetwork.class, ExtensionSelenium.class);

    private FoxhoundExportServer exportServer;
    private FoxhoundOptions options;
    private FoxhoundSeleniumProfile seleniumProfile;
    private FoxhoundLaunchButton launchButton = null;

    public ExtensionFoxhound() { super(NAME); }

    @Override
    public void init() {
        super.init();
        exportServer = new FoxhoundExportServer();
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

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

        exportServer.start(extensionNetwork, getOptions());

        // Load GUIs
        if (hasView()) {
            extensionHook.getHookView().addMainToolBarComponent(this.getLaunchButton());
            extensionHook.getHookView().addStatusPanel(new FoxhoundPanel(this));
        }

        LOGGER.info("Starting the Foxhound ZAP extension with {} sources and {} sinks.",
                FoxhoundConstants.ALL_SOURCES.size(), FoxhoundConstants.ALL_SINKS.size());
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
        exportServer.stop();
    }

    @Override
    public void unload() {
        super.unload();
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

    private FoxhoundSeleniumProfile getSeleniumProfile() {
        if (seleniumProfile == null) {
            seleniumProfile = new FoxhoundSeleniumProfile();
        }
        return seleniumProfile;
    }

    private FoxhoundLaunchButton getLaunchButton() {
        if (launchButton == null) {
            launchButton = new FoxhoundLaunchButton();
            launchButton.addActionListener(
                    e -> {
                        getSeleniumProfile().launchFoxhound();
                    }
            );
        }
        return launchButton;
    }
}