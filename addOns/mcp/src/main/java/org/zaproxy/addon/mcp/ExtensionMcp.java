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
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.mcp.automation.ImportMcpServerJob;
import org.zaproxy.addon.mcp.automation.McpConfigJob;
import org.zaproxy.addon.mcp.importer.ImportMcpServerDialog;
import org.zaproxy.addon.mcp.prompts.ZapBaselineScanPrompt;
import org.zaproxy.addon.mcp.prompts.ZapFullScanPrompt;
import org.zaproxy.addon.mcp.resources.AlertInstancesResource;
import org.zaproxy.addon.mcp.resources.AlertsResource;
import org.zaproxy.addon.mcp.resources.ContextsResource;
import org.zaproxy.addon.mcp.resources.HistoryEntryResource;
import org.zaproxy.addon.mcp.resources.HistoryResource;
import org.zaproxy.addon.mcp.resources.ReportTemplatesResource;
import org.zaproxy.addon.mcp.resources.ScanPoliciesResource;
import org.zaproxy.addon.mcp.resources.ScanStatusResource;
import org.zaproxy.addon.mcp.resources.SitesResource;
import org.zaproxy.addon.mcp.resources.SitesTreeResource;
import org.zaproxy.addon.mcp.tools.ZapCreateContextTool;
import org.zaproxy.addon.mcp.tools.ZapGenerateReportTool;
import org.zaproxy.addon.mcp.tools.ZapGetActiveScanStatusTool;
import org.zaproxy.addon.mcp.tools.ZapGetAjaxSpiderStatusTool;
import org.zaproxy.addon.mcp.tools.ZapGetPassiveScanStatusTool;
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
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.reports.ExtensionReports;
import org.zaproxy.zap.view.ZapMenuItem;

/** The MCP Integration add-on extension. */
public class ExtensionMcp extends ExtensionAdaptor {

    public static final String NAME = "ExtensionMcp";

    protected static final String PREFIX = "mcp";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(
                    ExtensionAutomation.class,
                    ExtensionHistory.class,
                    ExtensionNetwork.class,
                    ExtensionPassiveScan2.class,
                    ExtensionReports.class);

    private static final Logger LOGGER = LogManager.getLogger(ExtensionMcp.class);

    private Server server;
    private ImportMcpServerJob importMcpServerJob;
    private McpConfigJob mcpConfigJob;
    private McpParam param;
    private McpToolRegistry toolRegistry;
    private McpResourceRegistry resourceRegistry;
    private McpPromptRegistry promptRegistry;

    private int lastPort = -1;

    public ExtensionMcp() {
        super(NAME);
        setI18nPrefix(PREFIX);
        this.setOrder(800);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void init() {
        param = new McpParam();
        toolRegistry = new McpToolRegistry();
        resourceRegistry = new McpResourceRegistry();
        promptRegistry = new McpPromptRegistry();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addOptionsParamSet(param);
        extensionHook.addOptionsChangedListener(this::optionsChanged);
        extensionHook.addVariant(org.zaproxy.addon.mcp.importer.VariantMcpJsonRpc.class);

        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extAutomation != null) {
            importMcpServerJob = new ImportMcpServerJob();
            extAutomation.registerAutomationJob(importMcpServerJob);
            mcpConfigJob = new McpConfigJob();
            extAutomation.registerAutomationJob(mcpConfigJob);
        }

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(new McpOptionsPanel());

            ZapMenuItem importMenuItem = new ZapMenuItem("mcp.importserver.menu");
            importMenuItem.addActionListener(
                    e -> {
                        ImportMcpServerDialog dialog =
                                new ImportMcpServerDialog(View.getSingleton().getMainFrame());
                        dialog.setVisible(true);
                    });
            extensionHook.getHookMenu().addImportMenuItem(importMenuItem);
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
        toolRegistry.registerTool(new ZapGetPassiveScanStatusTool());
        toolRegistry.registerTool(new ZapGenerateReportTool());

        resourceRegistry.registerResource(new AlertsResource());
        resourceRegistry.registerResource(new AlertInstancesResource());
        resourceRegistry.registerResource(new ContextsResource());
        resourceRegistry.registerResource(new HistoryResource());
        resourceRegistry.registerResource(new HistoryEntryResource());
        resourceRegistry.registerResource(new ScanPoliciesResource());
        resourceRegistry.registerResource(new ScanStatusResource());
        resourceRegistry.registerResource(new SitesResource());
        resourceRegistry.registerResource(new SitesTreeResource());
        resourceRegistry.registerResource(new ReportTemplatesResource());

        promptRegistry.registerPrompt(new ZapBaselineScanPrompt());
        promptRegistry.registerPrompt(new ZapFullScanPrompt());
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

    /**
     * Returns the prompt registry for adding or removing MCP prompts.
     *
     * @return the prompt registry
     */
    public McpPromptRegistry getPromptRegistry() {
        return promptRegistry;
    }

    @Override
    public void start() {
        applyServerConfig();
    }

    private void optionsChanged(OptionsParam optionsParam) {
        if (lastPort != param.getPort()) {
            stopServer();
            startServer();
            lastPort = param.getPort();
        }
    }

    public McpParam getMcpParam() {
        return param;
    }

    /** Stops and restarts the MCP server using the current param values. */
    public void applyServerConfig() {
        if (server != null && (!param.isEnabled() || lastPort != param.getPort())) {
            stopServer();
        }

        if (param.isEnabled()) {
            startServer();
        }
    }

    private void startServer() {
        if (server != null || !param.isEnabled()) {
            return;
        }

        server =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionNetwork.class)
                        .createHttpServer(
                                new McpHttpMessageHandler(
                                        param,
                                        toolRegistry,
                                        resourceRegistry,
                                        promptRegistry,
                                        this.getAddOn().getVersion().toString()));
        try {
            int port = server.start(Server.DEFAULT_ADDRESS, param.getPort());
            lastPort = port;
            LOGGER.info("MCP HTTP listener started on {}:{}", Server.DEFAULT_ADDRESS, port);
        } catch (IOException e) {
            LOGGER.warn("Failed to start MCP HTTP listener on port {}", param.getPort(), e);
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

    @Override
    public void stop() {
        stopServer();
    }

    @Override
    public void unload() {
        stopServer();
        ExtensionAutomation extAutomation =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
        if (extAutomation != null) {
            if (importMcpServerJob != null) {
                extAutomation.unregisterAutomationJob(importMcpServerJob);
            }
            if (mcpConfigJob != null) {
                extAutomation.unregisterAutomationJob(mcpConfigJob);
            }
        }
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
