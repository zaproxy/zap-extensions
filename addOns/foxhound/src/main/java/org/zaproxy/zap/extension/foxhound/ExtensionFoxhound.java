package org.zaproxy.zap.extension.foxhound;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

import java.io.IOException;
import java.util.List;


public class ExtensionFoxhound extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionFoxhound.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionNetwork.class);

    private FoxhoundExportServer exportServer;
    private FoxhoundOptions options;

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

        extensionHook.addOptionsParamSet(getOptions());
        LOGGER.info("Loaded Foxhound Options {}", getOptions().getServerPort());

        ExtensionNetwork extensionNetwork =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);

        exportServer.start(extensionNetwork, getOptions());
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