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
 *   http://www.apache.org/licenses/LICENSE-2.0 
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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JFileChooser;
import javax.swing.SwingUtilities;

import org.apache.commons.httpclient.URI;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.spider.parser.SpiderParser;
import org.zaproxy.zap.view.ZapMenuItem;

import io.swagger.models.Scheme;

public class ExtensionOpenApi extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionOpenApi";

    private static final String THREAD_PREFIX = "ZAP-Import-OpenAPI-";

    private ZapMenuItem menuImportLocalOpenApi = null;
    private ZapMenuItem menuImportUrlOpenApi = null;
    private int threadId = 1;
    private SpiderParser customSpider;

    private CommandLineArgument[] arguments = new CommandLineArgument[2];
    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;

    private static final Logger LOG = Logger.getLogger(ExtensionOpenApi.class);

    public ExtensionOpenApi() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        
        /* Custom spider is added in order to explore Open API definitions. */
        ExtensionSpider spider = (ExtensionSpider) Control.getSingleton()
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
            extensionHook.getHookMenu().addToolsMenuItem(getMenuImportLocalOpenApi());
            extensionHook.getHookMenu().addToolsMenuItem(getMenuImportUrlOpenApi());
        }

        extensionHook.addApiImplementor(new OpenApiAPI(this));
        extensionHook.addCommandLine(getCommandLineArguments());
    }

    @Override
    public void unload() {
        super.unload();
        ExtensionSpider spider = (ExtensionSpider) Control.getSingleton()
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
            menuImportLocalOpenApi = new ZapMenuItem("openapi.topmenu.tools.importopenapi");
            menuImportLocalOpenApi.setToolTipText(Constant.messages.getString("openapi.topmenu.tools.importopenapi.tooltip"));

            menuImportLocalOpenApi.addActionListener(new java.awt.event.ActionListener() {

                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    // Prompt for a OpenApi file.
                    final JFileChooser chooser = new JFileChooser(Model.getSingleton().getOptionsParam().getUserDirectory());
                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {
                        Model.getSingleton().getOptionsParam().setUserDirectory(chooser.getCurrentDirectory());
                        importOpenApiDefinition(chooser.getSelectedFile(), true);
                    }

                }
            });
        }
        return menuImportLocalOpenApi;
    }

    /* Menu option to import a OpenApi file from a given URL. */
    private ZapMenuItem getMenuImportUrlOpenApi() {
        if (menuImportUrlOpenApi == null) {
            menuImportUrlOpenApi = new ZapMenuItem("openapi.topmenu.tools.importremoteopenapi");
            menuImportUrlOpenApi
                    .setToolTipText(Constant.messages.getString("openapi.topmenu.tools.importremoteopenapi.tooltip"));

            final ExtensionOpenApi shadowCopy = this;
            menuImportUrlOpenApi.addActionListener(new java.awt.event.ActionListener() {

                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    SwingUtilities.invokeLater(new Runnable() {

                        @Override
                        public void run() {
                            new ImportFromUrlDialog(View.getSingleton().getMainFrame(), shadowCopy);
                        }
                    });
                }
            });
        }
        return menuImportUrlOpenApi;
    }

    public void importOpenApiDefinition(final URI uri) {
        this.importOpenApiDefinition(uri, null, false);
    }

    public List<String> importOpenApiDefinition(final URI uri, final String siteOverride, boolean initViaUi) {
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(new HistoryPersister());
        try {
            return importOpenApiDefinition(
                    Scheme.forValue(uri.getScheme().toLowerCase()), uri.getAuthority(),
                    requestor.getResponseBody(uri), siteOverride, initViaUi);
        } catch (IOException e) {
            if (initViaUi) {
                View.getSingleton().showWarningDialog(Constant.messages.getString("openapi.io.error"));
            }
            LOG.warn(e.getMessage(), e);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    public void importOpenApiDefinition(final File file) {
        this.importOpenApiDefinition(file, false);
    }

    public List<String> importOpenApiDefinition(final File file, boolean initViaUi) {
        try {
            return importOpenApiDefinition(null, null, FileUtils.readFileToString(file, "UTF-8"), null, initViaUi);
        } catch (IOException e) {
            if (initViaUi) {
                View.getSingleton().showWarningDialog(Constant.messages.getString("openapi.io.error"));
            }
            LOG.warn(e.getMessage(), e);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
        return null;
    }

    private List<String> importOpenApiDefinition(final Scheme defaultScheme, final String defaultHost, final String defn, 
            final String hostOverride, final boolean initViaUi) {
        final List<String> errors = new ArrayList<String>();
        Thread t = new Thread(THREAD_PREFIX + threadId++) {

            @Override
            public void run() {
                try {
                    Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
                    requestor.setSiteOverride(hostOverride);
                    requestor.addListener(new HistoryPersister());
                    SwaggerConverter converter = new SwaggerConverter(
                            defaultScheme,
                            StringUtils.isNotEmpty(hostOverride) ? hostOverride : defaultHost,
                            defn,
                            getValueGenerator());
                    errors.addAll(requestor.run(converter.getRequestModels()));
                    // Needs to be called after converter.getRequestModels() to get loop errors
                    errors.addAll(converter.getErrorMessages());
                    if (errors.size() > 0) {
                        logErrors(errors, initViaUi);
                        if (initViaUi) {
                            View.getSingleton().showWarningDialog(Constant.messages.getString("openapi.parse.warn"));
                        }
                    } else {
                        if (initViaUi) {
                            View.getSingleton().showMessageDialog(Constant.messages.getString("openapi.parse.ok"));
                        }
                    }
                } catch (Exception e) {
                    if (initViaUi) {
                        String exMsg = e.getLocalizedMessage();
                        if (exMsg != null) {
                            exMsg = exMsg.length() >= 125 ? exMsg.substring(0, 122) + "..." : exMsg;
                        } else {
                            exMsg = "";
                        }
                        View.getSingleton().showWarningDialog(Constant.messages.getString("openapi.parse.error", exMsg)
                                + "\n\n" + Constant.messages.getString("openapi.parse.trailer"));
                    }
                    logErrors(errors, initViaUi);
                    LOG.warn(e.getMessage(), e);
                }
            }
            
        };
        t.start();
        
        if (! initViaUi) {
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
        ExtensionSpider spider = Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionSpider.class);
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
    public String getAuthor() {
        return Constant.ZAP_TEAM + " plus Joanna Bona, Artur Grzesica, Michal Materniak and Marcin Spiewak";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("openapi.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(Constant.ZAP_HOMEPAGE);
        } catch (MalformedURLException e) {
            return null;
        }
    }
    
    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_IMPORT_FILE_IDX] = new CommandLineArgument("-openapifile", 1, null, "", 
                "-openapifile <path>      " + Constant.messages.getString("openapi.cmdline.file.help"));
        arguments[ARG_IMPORT_URL_IDX] = new CommandLineArgument("-openapiurl", 1, null, "", 
                "-openapiurl <url>        " + Constant.messages.getString("openapi.cmdline.url.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_IMPORT_FILE_IDX].isEnabled()) {
            for (String file : args[ARG_IMPORT_FILE_IDX].getArguments()) {
                File f = new File(file);
                if (f.canRead()) {
                    List<String> errors = this.importOpenApiDefinition(f, false);
                    if (errors.size() > 0) {
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
                    URI url = new URI(urlstr, false);
                    List<String> errors = this.importOpenApiDefinition(url, null, false);
                    if (errors.size() > 0) {
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
