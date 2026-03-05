/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp;

import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.resources.AlertInstancesResource;
import org.zaproxy.addon.mcp.resources.AlertsResource;
import org.zaproxy.addon.mcp.resources.ContextsResource;
import org.zaproxy.addon.mcp.resources.HistoryEntryResource;
import org.zaproxy.addon.mcp.resources.HistoryResource;
import org.zaproxy.addon.mcp.resources.ScanPoliciesResource;
import org.zaproxy.addon.mcp.resources.ScanStatusResource;
import org.zaproxy.addon.mcp.resources.SitesResource;
import org.zaproxy.addon.mcp.resources.SitesTreeResource;
import org.zaproxy.addon.mcp.tools.ZapCreateContextTool;
import org.zaproxy.addon.mcp.tools.ZapGetActiveScanStatusTool;
import org.zaproxy.addon.mcp.tools.ZapGetAjaxSpiderStatusTool;
import org.zaproxy.addon.mcp.tools.ZapGetSpiderStatusTool;
import org.zaproxy.addon.mcp.tools.ZapInfoTool;
import org.zaproxy.addon.mcp.tools.ZapStartActiveScanTool;
import org.zaproxy.addon.mcp.tools.ZapStartAjaxSpiderTool;
import org.zaproxy.addon.mcp.tools.ZapStartSpiderTool;
import org.zaproxy.addon.mcp.tools.ZapStopActiveScanTool;
import org.zaproxy.addon.mcp.tools.ZapStopAjaxSpiderTool;
import org.zaproxy.addon.mcp.tools.ZapStopSpiderTool;
import org.zaproxy.addon.mcp.tools.ZapVersionTool;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.Server;

/**
 * The MCP add-on extension. Implements an MCP server in ZAP.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 */
public class ExtensionMcp extends ExtensionAdaptor {

    public static final String NAME = "ExtensionMcp";

    protected static final String PREFIX = "mcp";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAutomation.class, ExtensionNetwork.class);

    private static final Logger LOGGER = LogManager.getLogger(ExtensionMcp.class);

    private Server server;
    private final McpParam param = new McpParam();
    private final McpToolRegistry toolRegistry = new McpToolRegistry();
    private final McpResourceRegistry resourceRegistry = new McpResourceRegistry();

    public ExtensionMcp() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(param);
        extensionHook.addOptionsChangedListener(this::optionsChanged);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new McpOptionsPanel());
        }

        toolRegistry.registerTool(new ZapVersionTool());
        toolRegistry.registerTool(new ZapInfoTool());
        toolRegistry.registerTool(new ZapCreateContextTool());
        toolRegistry.registerTool(new ZapStartSpiderTool());
        toolRegistry.registerTool(new ZapStopSpiderTool());
        toolRegistry.registerTool(new ZapGetSpiderStatusTool());
        toolRegistry.registerTool(new ZapStartAjaxSpiderTool());
        toolRegistry.registerTool(new ZapStopAjaxSpiderTool());
        toolRegistry.registerTool(new ZapGetAjaxSpiderStatusTool());
        toolRegistry.registerTool(new ZapStartActiveScanTool());
        toolRegistry.registerTool(new ZapStopActiveScanTool());
        toolRegistry.registerTool(new ZapGetActiveScanStatusTool());

        resourceRegistry.registerResource(new AlertsResource());
        resourceRegistry.registerResource(new AlertInstancesResource());
        resourceRegistry.registerResource(new ContextsResource());
        resourceRegistry.registerResource(new HistoryResource());
        resourceRegistry.registerResource(new HistoryEntryResource());
        resourceRegistry.registerResource(new ScanPoliciesResource());
        resourceRegistry.registerResource(new ScanStatusResource());
        resourceRegistry.registerResource(new SitesResource());
        resourceRegistry.registerResource(new SitesTreeResource());
    }

    /**
     * Returns the tool registry for adding or removing MCP tools.
     *
     * @return the tool registry
     */
    public McpToolRegistry getToolRegistry() {
        return toolRegistry;
    }

    /**
     * Returns the resource registry for adding or removing MCP resources.
     *
     * @return the resource registry
     */
    public McpResourceRegistry getResourceRegistry() {
        return resourceRegistry;
    }

    @Override
    public void optionsLoaded() {
        super.optionsLoaded();

        startServer();
    }

    private void optionsChanged(OptionsParam optionsParam) {
        stopServer();
        startServer();
    }

    private void startServer() {
        if (server != null) {
            return;
        }

        server =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionNetwork.class)
                        .createHttpServer(
                                new McpHttpMessageHandler(
                                        param, toolRegistry, resourceRegistry, getAddOnVersion()));
        try {
            int port = server.start(Server.DEFAULT_ADDRESS, param.getPort());
            LOGGER.info("MCP HTTP listener started on {}:{}", Server.DEFAULT_ADDRESS, port);
        } catch (IOException e) {
            LOGGER.error("Failed to start MCP HTTP listener on port {}", param.getPort(), e);
            server = null;
        }
    }

    private void stopServer() {
        if (server != null) {
            try {
                server.stop();
                LOGGER.info("MCP HTTP listener stopped");
            } catch (IOException e) {
                LOGGER.debug("An error occurred while stopping the MCP HTTP listener.", e);
            }
            server = null;
        }
    }

    private String getAddOnVersion() {
        return this.getAddOn().getVersion().toString();
    }

    @Override
    public void unload() {
        stopServer();
        super.unload();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }
}
