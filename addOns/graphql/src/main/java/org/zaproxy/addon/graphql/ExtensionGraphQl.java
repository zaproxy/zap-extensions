/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionGraphQl extends ExtensionAdaptor
        implements CommandLineListener, SessionChangedListener, ExampleAlertProvider {

    public static final String NAME = "ExtensionGraphQl";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionCommonlib.class);

    static final int TOOL_ALERT_ID = 50007;
    private static final Logger LOGGER = LogManager.getLogger(ExtensionGraphQl.class);

    private ZapMenuItem menuImportGraphQl;
    private GraphQlOptionsPanel graphQlOptionsPanel;
    private GraphQlParam param;
    private List<ParserThread> parserThreads = Collections.synchronizedList(new ArrayList<>());
    private ImportDialog importDialog;

    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_END_URL_IDX = 2;

    public ExtensionGraphQl() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    ValueGenerator getValueGenerator() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCommonlib.class)
                .getValueGenerator();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportGraphQl());
            extensionHook.getHookView().addOptionPanel(getGraphQlOptionsPanel());
        }

        extensionHook.addVariant(VariantGraphQl.class);
        extensionHook.addApiImplementor(new GraphQlApi(getParam()));
        extensionHook.addOptionsParamSet(getParam());
        extensionHook.addCommandLine(getCommandLineArguments());
        extensionHook.addSessionListener(this);
    }

    @Override
    public void postInit() {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        String scriptName = "GraphQL Support.js";
        if (extScript != null && extScript.getScript(scriptName) != null) {
            extScript.removeScript(extScript.getScript(scriptName));
        }
    }

    @Override
    public void unload() {
        super.unload();
        if (importDialog != null) {
            importDialog.dispose();
        }
    }

    private ZapMenuItem getMenuImportGraphQl() {
        if (menuImportGraphQl == null) {
            menuImportGraphQl = new ZapMenuItem("graphql.topmenu.import.importgraphql");
            menuImportGraphQl.setToolTipText(
                    Constant.messages.getString("graphql.topmenu.import.importgraphql.tooltip"));
            menuImportGraphQl.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame());
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuImportGraphQl;
    }

    private GraphQlOptionsPanel getGraphQlOptionsPanel() {
        if (graphQlOptionsPanel == null) {
            graphQlOptionsPanel = new GraphQlOptionsPanel();
        }
        return graphQlOptionsPanel;
    }

    public GraphQlParam getParam() {
        if (param == null) {
            param = new GraphQlParam();
        }
        return param;
    }

    protected void addParserThread(ParserThread thread) {
        parserThreads.add(thread);
    }

    private void stopParserThreads() {
        synchronized (parserThreads) {
            for (ParserThread thread : parserThreads) {
                if (thread.isRunning()) {
                    LOGGER.debug("Stopping Thread {}", thread.getName());
                    thread.stopParser();
                }
            }
        }
        parserThreads.clear();
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/graphql-support/alerts/#id-"
                + TOOL_ALERT_ID;
    }

    @Override
    public void sessionAboutToChange(Session arg0) {
        stopParserThreads();
        if (importDialog != null) {
            importDialog.clearFields();
        }
    }

    @Override
    public void sessionChanged(Session arg0) {}

    @Override
    public void sessionModeChanged(Mode mode) {}

    @Override
    public void sessionScopeChanged(Session arg0) {}

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("graphql.desc");
    }

    private CommandLineArgument[] getCommandLineArguments() {
        CommandLineArgument[] args = new CommandLineArgument[3];
        args[ARG_IMPORT_FILE_IDX] =
                new CommandLineArgument(
                        "-graphqlfile",
                        1,
                        null,
                        "",
                        "-graphqlfile <path>       "
                                + Constant.messages.getString("graphql.cmdline.file.help"));
        args[ARG_IMPORT_URL_IDX] =
                new CommandLineArgument(
                        "-graphqlurl",
                        1,
                        null,
                        "",
                        "-graphqlurl <url>         "
                                + Constant.messages.getString("graphql.cmdline.url.help"));
        args[ARG_END_URL_IDX] =
                new CommandLineArgument(
                        "-graphqlendurl",
                        1,
                        null,
                        "",
                        "-graphqlendurl <url>      "
                                + Constant.messages.getString("graphql.cmdline.endurl.help"));
        return args;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (args[ARG_IMPORT_FILE_IDX].isEnabled() || args[ARG_IMPORT_URL_IDX].isEnabled()) {
            if (!args[ARG_END_URL_IDX].isEnabled()) {
                CommandLine.error(Constant.messages.getString("graphql.error.emptyendurl"));
                return;
            }

            GraphQlParser parser;
            try {
                parser =
                        new GraphQlParser(
                                args[ARG_END_URL_IDX].getArguments().firstElement(),
                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                true);
                parser.addRequesterListener(new HistoryPersister());
            } catch (URIException e) {
                CommandLine.error(
                        Constant.messages.getString("graphql.error.invalidurl", e.getMessage()));
                return;
            }

            if (args[ARG_IMPORT_FILE_IDX].isEnabled()) {
                try {
                    parser.importFile(args[ARG_IMPORT_FILE_IDX].getArguments().firstElement());
                } catch (IOException e) {
                    CommandLine.error(e.getMessage());
                }
            } else if (args[ARG_IMPORT_URL_IDX].isEnabled()) {
                try {
                    parser.importUrl(args[ARG_IMPORT_URL_IDX].getArguments().firstElement());
                } catch (IOException e) {
                    CommandLine.error(
                            Constant.messages.getString(
                                    "graphql.error.invalidurl", e.getMessage()));
                }
            }
        } else if (args[ARG_END_URL_IDX].isEnabled()) {
            try {
                GraphQlParser parser =
                        new GraphQlParser(
                                args[ARG_END_URL_IDX].getArguments().firstElement(),
                                HttpSender.MANUAL_REQUEST_INITIATOR,
                                true);
                parser.addRequesterListener(new HistoryPersister());
                parser.introspect();
            } catch (IOException e) {
                CommandLine.error(
                        Constant.messages.getString("graphql.error.invalidurl", e.getMessage()));
            }
        }
    }

    @Override
    public List<String> getHandledExtensions() {
        return null;
    }

    @Override
    public boolean handleFile(File file) {
        // Not supported
        return false;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                GraphQlParser.createIntrospectionAlert().build(),
                GraphQlFingerprinter.createFingerprintingAlert("example").build());
    }
}
