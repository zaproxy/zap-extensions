/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.ui.ProgressPane;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;
import org.zaproxy.zap.extension.openapi.converter.swagger.InvalidUrlException;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.RequestModel;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionOpenApi extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionOpenApi";

    public static final String URL_ADDED_STATS = "openapi.urls.added";

    private static final String THREAD_PREFIX = "ZAP-Import-OpenAPI-";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(Arrays.asList(ExtensionCommonlib.class));

    private ZapMenuItem menuImportLocalOpenApi = null;
    private ZapMenuItem menuImportUrlOpenApi = null;
    private ImportFromFileDialog currentFileDialog = null;
    private ImportFromUrlDialog currentUrlDialog = null;
    private int threadId = 1;
    private SpiderParser customSpider;
    private ValueGenerator valueGenerator;

    private CommandLineArgument[] arguments = new CommandLineArgument[3];
    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_TARGET_URL_IDX = 2;

    private static final Logger LOG = LogManager.getLogger(ExtensionOpenApi.class);

    public ExtensionOpenApi() {
        super(NAME);
        setValueGenerator(null);
    }

    public void setValueGenerator(ValueGenerator valueGenerator) {
        this.valueGenerator = valueGenerator == null ? new DefaultValueGenerator() : valueGenerator;
    }

    public ValueGenerator getValueGenerator() {
        return valueGenerator;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        /* Custom spider is added in order to explore Open API definitions. */
        ExtensionSpider spider =
                (ExtensionSpider)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionSpider.NAME);
        if (spider != null) {
            customSpider = new OpenApiSpider(this::getValueGenerator);
            spider.addCustomParser(customSpider);
            LOG.debug("Added custom Open API spider.");
        } else {
            LOG.debug("Custom Open API spider could not be added.");
        }

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalOpenApi());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlOpenApi());
            extensionHook.addSessionListener(new SessionChangedListenerImpl());
            extensionHook.getHookView().addStatusPanel(getProgressPanel());
        }

        extensionHook.addApiImplementor(new OpenApiAPI(this));
        extensionHook.addCommandLine(getCommandLineArguments());
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionSpider spider =
                (ExtensionSpider)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionSpider.NAME);
        if (spider != null) {
            spider.removeCustomParser(customSpider);
            LOG.debug("Removed custom Open API spider.");
        }
        if (currentFileDialog != null) {
            currentFileDialog.dispose();
        }
        if (currentUrlDialog != null) {
            currentUrlDialog.dispose();
        }
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    private ProgressPanel getProgressPanel() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionCommonlib.class)
                .getProgressPanel();
    }

    /* Menu option to import a local OpenApi file. */
    private ZapMenuItem getMenuImportLocalOpenApi() {
        if (menuImportLocalOpenApi == null) {
            menuImportLocalOpenApi = new ZapMenuItem("openapi.topmenu.import.importopenapi");
            menuImportLocalOpenApi.setToolTipText(
                    Constant.messages.getString("openapi.topmenu.import.importopenapi.tooltip"));
            menuImportLocalOpenApi.addActionListener(
                    e -> {
                        if (currentFileDialog == null) {
                            currentFileDialog =
                                    new ImportFromFileDialog(
                                            View.getSingleton().getMainFrame(),
                                            ExtensionOpenApi.this);
                        } else {
                            currentFileDialog.setVisible(true);
                        }
                    });
        }
        return menuImportLocalOpenApi;
    }

    /* Menu option to import a OpenApi file from a given URL. */
    private ZapMenuItem getMenuImportUrlOpenApi() {
        if (menuImportUrlOpenApi == null) {
            menuImportUrlOpenApi = new ZapMenuItem("openapi.topmenu.import.importremoteopenapi");
            menuImportUrlOpenApi.setToolTipText(
                    Constant.messages.getString(
                            "openapi.topmenu.import.importremoteopenapi.tooltip"));

            menuImportUrlOpenApi.addActionListener(
                    e -> {
                        if (currentUrlDialog == null) {
                            currentUrlDialog =
                                    new ImportFromUrlDialog(
                                            View.getSingleton().getMainFrame(),
                                            ExtensionOpenApi.this);
                        } else {
                            currentUrlDialog.setVisible(true);
                        }
                    });
        }
        return menuImportUrlOpenApi;
    }

    public void importOpenApiDefinition(final URI uri) {
        this.importOpenApiDefinition(uri, null, false);
    }

    /**
     * Imports the API definition from a URI.
     *
     * @param uri the URI locating the API definition.
     * @param targetUrl the URL to override the URL defined in the API, might be {@code null}.
     * @param initViaUi {@code true} if the import is being done through the GUI, {@code false}
     *     otherwise.
     * @return the list of errors, if any. Returns {@code null} if the import is being done through
     *     the GUI, or, if not done through the GUI the target was not accessed (caused by an {@code
     *     IOException}).
     * @throws InvalidUrlException if the target URL is not valid.
     */
    public List<String> importOpenApiDefinition(
            final URI uri, final String targetUrl, boolean initViaUi) {
        OpenApiResults results = this.importOpenApiDefinitionV2(uri, targetUrl, initViaUi);
        if (results != null) {
            return results.getErrors();
        }
        return null;
    }

    public OpenApiResults importOpenApiDefinitionV2(
            final URI uri, final String targetUrl, boolean initViaUi) {
        return importOpenApiDefinitionV2(uri, targetUrl, initViaUi, -1);
    }

    /**
     * Imports the API definition from a URI.
     *
     * @param uri the URI locating the API definition.
     * @param targetUrl the URL to override the URL defined in the API, might be {@code null}.
     * @param initViaUi {@code true} if the import is being done through the GUI, {@code false}
     *     otherwise.
     * @param contextId The contextId to add structural modifiers (data driven nodes) from openapi
     *     spec path parameters {@code null}
     * @return the list of errors, if any. Returns {@code null} if the import is being done through
     *     the GUI, or, if not done through the GUI the target was not accessed (caused by an {@code
     *     IOException}).
     * @throws InvalidUrlException if the target URL is not valid.
     */
    public List<String> importOpenApiDefinition(
            final URI uri, final String targetUrl, boolean initViaUi, int contextId) {
        return this.importOpenApiDefinitionV2(uri, targetUrl, initViaUi, contextId).getErrors();
    }

    public OpenApiResults importOpenApiDefinitionV2(
            final URI uri, final String targetUrl, boolean initViaUi, int contextId) {
        OpenApiResults results = new OpenApiResults();
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(new HistoryPersister(results));
        try {
            String path = uri.getPath();
            if (path == null) {
                path = "";
            }
            results.setErrors(
                    importOpenApiDefinition(
                            requestor.getResponseBody(uri),
                            targetUrl,
                            uri.getScheme() + "://" + uri.getAuthority() + path,
                            initViaUi,
                            requestor,
                            contextId));
            return results;
        } catch (IOException e) {
            if (initViaUi) {
                View.getSingleton()
                        .showWarningDialog(Constant.messages.getString("openapi.io.error"));
            }
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    public void importOpenApiDefinition(final File file) {
        this.importOpenApiDefinition(file, false);
    }

    public List<String> importOpenApiDefinition(final File file, boolean initViaUi) {
        return this.importOpenApiDefinition(file, null, initViaUi);
    }

    /**
     * Imports the API definition from a file.
     *
     * @param file the file with the API definition.
     * @param targetUrl the URL to override the URL defined in the API, might be {@code null}.
     * @param initViaUi {@code true} if the import is being done through the GUI, {@code false}
     *     otherwise.
     * @return the list of errors, if any. Returns {@code null} if the import is being done through
     *     the GUI.
     * @throws InvalidUrlException if the target URL is not valid.
     */
    public List<String> importOpenApiDefinition(
            final File file, final String targetUrl, boolean initViaUi) {
        OpenApiResults results = this.importOpenApiDefinitionV2(file, targetUrl, initViaUi);
        if (results != null) {
            return results.getErrors();
        }
        return null;
    }

    public OpenApiResults importOpenApiDefinitionV2(
            final File file, final String targetUrl, boolean initViaUi) {
        return importOpenApiDefinitionV2(file, targetUrl, initViaUi, -1);
    }

    /**
     * Imports the API definition from a file.
     *
     * @param file the file with the API definition.
     * @param targetUrl the URL to override the URL defined in the API, might be {@code null}.
     * @param initViaUi {@code true} if the import is being done through the GUI, {@code false}
     *     otherwise.
     * @param contextId The contextId to add structural modifiers (data driven nodes) from openapi
     *     spec path parameters {@code null}
     * @return the list of errors, if any. Returns {@code null} if the import is being done through
     *     the GUI.
     * @throws InvalidUrlException if the target URL is not valid.
     */
    public List<String> importOpenApiDefinition(
            final File file, final String targetUrl, boolean initViaUi, int contextId) {
        return this.importOpenApiDefinitionV2(file, targetUrl, initViaUi, contextId).getErrors();
    }

    public OpenApiResults importOpenApiDefinitionV2(
            final File file, final String targetUrl, boolean initViaUi, int contextId) {
        try {
            OpenApiResults results = new OpenApiResults();
            Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
            requestor.addListener(new HistoryPersister(results));

            if (!file.exists()) {
                throw new IOException(file.getAbsolutePath() + " does not exist.");
            }

            SwaggerParseResult swaggerParseResult = SwaggerConverter.parse(file);
            OpenAPI openApi = swaggerParseResult.getOpenAPI();

            List<String> errors;
            if (openApi == null) {
                errors = swaggerParseResult.getMessages();
            } else {
                errors =
                        importOpenApiDefinition(
                                Json.pretty(openApi),
                                targetUrl,
                                null,
                                initViaUi,
                                requestor,
                                contextId);
            }
            results.setErrors(errors);
            return results;
        } catch (IOException e) {
            if (initViaUi) {
                View.getSingleton()
                        .showWarningDialog(Constant.messages.getString("openapi.io.error"));
            }
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    private List<String> importOpenApiDefinition(
            String defn,
            final String targetUrl,
            final String definitionUrl,
            boolean initViaUi,
            final Requestor requestor,
            int contextId) {
        final List<String> errors = new ArrayList<>();
        SwaggerConverter converter =
                new SwaggerConverter(targetUrl, definitionUrl, defn, getValueGenerator());
        Thread t =
                new Thread(THREAD_PREFIX + threadId++) {

                    @Override
                    public void run() {
                        ProgressPane currentImportPane = null;
                        try {
                            List<RequestModel> requestModels = converter.getRequestModels();
                            converter.setStructuralNodeModifiers(contextId);

                            if (initViaUi) {
                                currentImportPane = new ProgressPane();
                                requestor.addListener(new ProgressListener(currentImportPane));
                                currentImportPane.setTotalTasks(requestModels.size());
                                getProgressPanel().addProgressPane(currentImportPane);
                            }
                            errors.addAll(requestor.run(requestModels));
                            // Needs to be called after converter.getRequestModels() to get loop
                            // errors
                            errors.addAll(converter.getErrorMessages());
                            if (!errors.isEmpty()) {
                                logErrors(errors, initViaUi);
                                if (initViaUi) {
                                    View.getSingleton()
                                            .showWarningDialog(
                                                    Constant.messages.getString(
                                                            "openapi.parse.warn"));
                                }
                            } else {
                                if (initViaUi) {
                                    View.getSingleton()
                                            .showMessageDialog(
                                                    Constant.messages.getString(
                                                            "openapi.parse.ok"));
                                }
                            }
                        } catch (Exception e) {
                            if (initViaUi) {
                                String exMsg = e.getLocalizedMessage();
                                if (exMsg != null) {
                                    exMsg =
                                            exMsg.length() >= 125
                                                    ? exMsg.substring(0, 122) + "..."
                                                    : exMsg;
                                } else {
                                    exMsg = "";
                                }
                                String baseMessage =
                                        Constant.messages.getString("openapi.parse.error", exMsg);
                                View.getSingleton().getOutputPanel().append(baseMessage);
                                View.getSingleton().getOutputPanel().append(e);
                                View.getSingleton()
                                        .showWarningDialog(
                                                baseMessage
                                                        + "\n\n"
                                                        + Constant.messages.getString(
                                                                "openapi.parse.trailer"));
                            }
                            errors.add(Constant.messages.getString("openapi.parse.error", e));
                            logErrors(errors, initViaUi);
                            LOG.warn(e.getMessage(), e);
                        } finally {
                            if (currentImportPane != null) {
                                currentImportPane.completed();
                            }
                        }
                    }
                };
        t.start();

        if (!initViaUi) {
            try {
                t.join();
            } catch (InterruptedException e) {
                LOG.debug(e.getMessage(), e);
            }
            return errors;
        }
        return null;
    }

    private void logErrors(List<String> errors, boolean initViaUi) {
        if (errors != null) {
            for (String error : errors) {
                if (initViaUi) {
                    View.getSingleton().getOutputPanel().append(error + "\n");
                } else {
                    LOG.warn(error);
                }
            }
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("openapi.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.desc");
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_IMPORT_FILE_IDX] =
                new CommandLineArgument(
                        "-openapifile",
                        1,
                        null,
                        "",
                        "-openapifile <path>      "
                                + Constant.messages.getString("openapi.cmdline.file.help"));
        arguments[ARG_IMPORT_URL_IDX] =
                new CommandLineArgument(
                        "-openapiurl",
                        1,
                        null,
                        "",
                        "-openapiurl <url>        "
                                + Constant.messages.getString("openapi.cmdline.url.help"));
        arguments[ARG_TARGET_URL_IDX] =
                new CommandLineArgument(
                        "-openapitargeturl",
                        1,
                        null,
                        "",
                        "-openapitargeturl <url>  "
                                + Constant.messages.getString("openapi.cmdline.targeturl.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_IMPORT_FILE_IDX].isEnabled()) {
            for (String file : args[ARG_IMPORT_FILE_IDX].getArguments()) {
                File f = new File(file);
                if (f.canRead()) {
                    List<String> errors = new ArrayList<>();
                    if (arguments[ARG_TARGET_URL_IDX].isEnabled()) {
                        for (String target : arguments[ARG_TARGET_URL_IDX].getArguments()) {
                            try {
                                errors.addAll(this.importOpenApiDefinition(f, target, false));
                            } catch (InvalidUrlException e) {
                                CommandLine.error(e.getMessage());
                            }
                        }
                    } else {
                        errors.addAll(this.importOpenApiDefinition(f, null, false));
                    }

                    if (!errors.isEmpty()) {
                        for (String error : errors) {
                            CommandLine.error("Error importing definition: " + error);
                        }
                    }
                } else {
                    CommandLine.error("Cannot read Open API file: " + f.getAbsolutePath());
                }
            }
        }
        if (arguments[ARG_IMPORT_URL_IDX].isEnabled()) {
            for (String urlstr : args[ARG_IMPORT_URL_IDX].getArguments()) {
                try {
                    List<String> errors = new ArrayList<>();
                    URI url = new URI(urlstr, false);
                    if (arguments[ARG_TARGET_URL_IDX].isEnabled()) {
                        for (String target : arguments[ARG_TARGET_URL_IDX].getArguments()) {
                            try {
                                errors.addAll(this.importOpenApiDefinition(url, target, false));
                            } catch (InvalidUrlException e) {
                                CommandLine.error(e.getMessage());
                            }
                        }
                    } else {
                        errors.addAll(this.importOpenApiDefinition(url, null, false));
                    }
                    if (!errors.isEmpty()) {
                        for (String error : errors) {
                            CommandLine.error("Error importing definition: " + error);
                        }
                    }
                } catch (Exception e) {
                    CommandLine.error(e.getMessage(), e);
                }
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

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            if (currentFileDialog != null) {
                currentFileDialog.clear();
            }
            if (currentUrlDialog != null) {
                currentUrlDialog.clear();
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }
}
