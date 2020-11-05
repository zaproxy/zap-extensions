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
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.spider.filters.ParseFilter;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionGraphQl extends ExtensionAdaptor
        implements CommandLineListener, SessionChangedListener {

    public static final String NAME = "ExtensionGraphQl";
    private static final Logger LOG = Logger.getLogger(ExtensionGraphQl.class);

    private ZapMenuItem menuImportLocalGraphQl = null;
    private ZapMenuItem menuImportUrlGraphQl = null;
    private SpiderParser graphQlSpider;
    private ParseFilter graphQlParseFilter;
    private GraphQlOptionsPanel graphQlOptionsPanel;
    private GraphQlParam param;
    private List<ParserThread> parserThreads = Collections.synchronizedList(new ArrayList<>());

    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_END_URL_IDX = 2;

    public ExtensionGraphQl() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (!"2.9.0".equals(Constant.PROGRAM_VERSION)) {
            /* Custom spider is added in order to explore GraphQl schemas. */
            ExtensionSpider spider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
            graphQlSpider = new GraphQlSpider();
            graphQlParseFilter = new GraphQlParseFilter();
            if (spider != null) {
                spider.addCustomParseFilter(graphQlParseFilter);
                spider.addCustomParser(graphQlSpider);
                LOG.debug("Added GraphQl spider.");
            } else {
                LOG.debug("Could not add GraphQl spider.");
            }
        }

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalGraphQl());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlGraphQl());
            extensionHook.getHookView().addOptionPanel(getGraphQlOptionsPanel());
        }

        extensionHook.addApiImplementor(new GraphQlApi(getParam()));
        extensionHook.addOptionsParamSet(getParam());
        extensionHook.addCommandLine(getCommandLineArguments());
        extensionHook.addSessionListener(this);
    }

    @Override
    public void postInit() {
        super.postInit();
        try {
            addScript();
        } catch (IOException e) {
            LOG.warn("Could not add GraphQL Input Vectors script.");
        }
    }

    @Override
    public void unload() {
        super.unload();
        if (!"2.9.0".equals(Constant.PROGRAM_VERSION)) {
            ExtensionSpider spider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
            if (spider != null) {
                spider.removeCustomParseFilter(graphQlParseFilter);
                spider.removeCustomParser(graphQlSpider);
                LOG.debug("Removed GraphQl spider.");
            }
        }
    }

    /* Menu option to import a local GraphQl file. */
    private ZapMenuItem getMenuImportLocalGraphQl() {
        if (menuImportLocalGraphQl == null) {
            menuImportLocalGraphQl = new ZapMenuItem("graphql.topmenu.import.importgraphql");
            menuImportLocalGraphQl.setToolTipText(
                    Constant.messages.getString("graphql.topmenu.import.importgraphql.tooltip"));
            menuImportLocalGraphQl.addActionListener(
                    e -> new ImportFromFileDialog(View.getSingleton().getMainFrame()));
        }
        return menuImportLocalGraphQl;
    }

    /* Menu option to import a GraphQl file from a given URL. */
    private ZapMenuItem getMenuImportUrlGraphQl() {
        if (menuImportUrlGraphQl == null) {
            menuImportUrlGraphQl = new ZapMenuItem("graphql.topmenu.import.importremotegraphql");
            menuImportUrlGraphQl.setToolTipText(
                    Constant.messages.getString(
                            "graphql.topmenu.import.importremotegraphql.tooltip"));

            menuImportUrlGraphQl.addActionListener(
                    e -> new ImportFromUrlDialog(View.getSingleton().getMainFrame()));
        }
        return menuImportUrlGraphQl;
    }

    private GraphQlOptionsPanel getGraphQlOptionsPanel() {
        if (graphQlOptionsPanel == null) {
            graphQlOptionsPanel = new GraphQlOptionsPanel();
        }
        return graphQlOptionsPanel;
    }

    protected GraphQlParam getParam() {
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
                    LOG.debug("Stopping Thread " + thread.getName());
                    thread.stopParser();
                }
            }
        }
        parserThreads.clear();
    }

    private void addScript() throws IOException {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        String scriptName = "GraphQL Support.js";
        if (extScript != null && extScript.getScript(scriptName) == null) {
            ScriptType variantType =
                    extScript.getScriptType(ExtensionActiveScan.SCRIPT_TYPE_VARIANT);
            ScriptEngineWrapper engine = extScript.getEngineWrapper("Oracle Nashorn");
            if (variantType != null && engine != null) {
                File scriptPath =
                        Paths.get(
                                        Constant.getZapHome(),
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionScript.SCRIPTS_DIR,
                                        ExtensionActiveScan.SCRIPT_TYPE_VARIANT,
                                        scriptName)
                                .toFile();
                ScriptWrapper script =
                        new ScriptWrapper(
                                scriptName,
                                Constant.messages.getString("graphql.script.description"),
                                engine,
                                variantType,
                                true,
                                scriptPath);
                script.setLoadOnStart(true);
                script.reloadScript();
                extScript.addScript(script, false);
            }
        }
    }

    @Override
    public void sessionAboutToChange(Session arg0) {
        stopParserThreads();
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
}
