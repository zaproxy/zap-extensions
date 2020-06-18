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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.openapi.converter.swagger.InvalidUrlException;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionOpenApi extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionOpenApi";

    private static final String THREAD_PREFIX = "ZAP-Import-OpenAPI-";

    private ZapMenuItem menuImportLocalOpenApi = null;
    private ZapMenuItem menuImportUrlOpenApi = null;
    private int threadId = 1;
    private SpiderParser customSpider;

    private CommandLineArgument[] arguments = new CommandLineArgument[3];
    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_TARGET_URL_IDX = 2;

    private static final Logger LOG = Logger.getLogger(ExtensionOpenApi.class);

    public ExtensionOpenApi() {
        super(NAME);
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
        customSpider = new OpenApiSpider();
        if (spider != null) {
            spider.addCustomParser(customSpider);
            LOG.debug("Added custom Open API spider.");
        } else {
            LOG.warn("Custom Open API spider could not be added.");
        }

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalOpenApi());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlOpenApi());
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
    }

    /* Menu option to import a local OpenApi file. */
    private ZapMenuItem getMenuImportLocalOpenApi() {
        if (menuImportLocalOpenApi == null) {
            menuImportLocalOpenApi = new ZapMenuItem("openapi.topmenu.import.importopenapi");
            menuImportLocalOpenApi.setToolTipText(
                    Constant.messages.getString("openapi.topmenu.import.importopenapi.tooltip"));
            menuImportLocalOpenApi.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            new ImportFromFileDialog(
                                    View.getSingleton().getMainFrame(), ExtensionOpenApi.this);
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

            final ExtensionOpenApi shadowCopy = this;
            menuImportUrlOpenApi.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            new ImportFromUrlDialog(View.getSingleton().getMainFrame(), shadowCopy);
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
     *     the GUI.
     * @throws InvalidUrlException if the target URL is not valid.
     */
    public List<String> importOpenApiDefinition(
            final URI uri, final String targetUrl, boolean initViaUi) {
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(new HistoryPersister());
        try {
            String path = uri.getPath();
            if (path == null) {
                path = "";
            }
            return importOpenApiDefinition(
                    requestor.getResponseBody(uri),
                    targetUrl,
                    uri.getScheme() + "://" + uri.getAuthority() + path,
                    initViaUi);
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
        try {
            return importOpenApiDefinition(
                    FileUtils.readFileToString(file, "UTF-8"), targetUrl, null, initViaUi);
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
            String defn, final String targetUrl, final String definitionUrl, boolean initViaUi) {
        final List<String> errors = new ArrayList<>();
        SwaggerConverter converter =
                new SwaggerConverter(targetUrl, definitionUrl, defn, getValueGenerator());
        Thread t =
                new Thread(THREAD_PREFIX + threadId++) {

                    @Override
                    public void run() {
                        try {
                            Requestor requestor =
                                    new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
                            requestor.addListener(new HistoryPersister());
                            errors.addAll(requestor.run(converter.getRequestModels()));
                            // Needs to be called after converter.getRequestModels() to get loop
                            // errors
                            errors.addAll(converter.getErrorMessages());
                            if (errors.size() > 0) {
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
                            logErrors(errors, initViaUi);
                            LOG.warn(e.getMessage(), e);
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

    private ValueGenerator getValueGenerator() {
        // Always get the latest ValueGenerator as it could have changed
        ExtensionSpider spider =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
        if (spider != null) {
            return spider.getValueGenerator();
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
}
