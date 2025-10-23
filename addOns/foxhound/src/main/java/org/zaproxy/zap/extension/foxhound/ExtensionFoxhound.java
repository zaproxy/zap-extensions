package org.zaproxy.zap.extension.foxhound;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundOptions;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundSeleniumProfile;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProfileManager;

import java.awt.EventQueue;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;


public class ExtensionFoxhound extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionFoxhound.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionNetwork.class);

    private FoxhoundExportServer exportServer;
    private FoxhoundOptions options;
    private FoxhoundSeleniumProfile seleniumProfile;

    @Override
    public void init() {
        LOGGER.info("Starting the Foxhound ZAP extension");
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

        FoxhoundOptions options = getOptions();
        extensionHook.addOptionsParamSet(options);

        // Automatically update options in the selenium profile if they are changed
        seleniumProfile = new FoxhoundSeleniumProfile(options);
        options.addPropertyChangeListener(e -> seleniumProfile.writeOptionsToProfile());

        ExtensionNetwork extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);

        exportServer.start(extensionNetwork, getOptions());
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
    public String getName() {
        return "ExtensionFoxhound";
    }

    @Override
    public String getDescription() {
        return "Foxhound";
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public FoxhoundOptions getOptions() {
        if (options == null) {
            options = new FoxhoundOptions();
        }
        return options;
    }
}