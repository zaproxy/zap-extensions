/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman;

import java.io.File;
import java.util.List;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionPostman extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionPostman";

    private ZapMenuItem menuImportPostmanCollection;
    private ImportDialog importDialog;

    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_ENDPOINT_URL_IDX = 2;

    public ExtensionPostman() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportPostmanCollection());
            extensionHook.addSessionListener(new SessionChangedListenerImpl());
        }
        extensionHook.addApiImplementor(new PostmanApi());
        extensionHook.addCommandLine(getCommandLineArguments());
    }

    private ZapMenuItem getMenuImportPostmanCollection() {
        if (menuImportPostmanCollection == null) {
            menuImportPostmanCollection = new ZapMenuItem("postman.topmenu.import");
            menuImportPostmanCollection.setToolTipText(
                    Constant.messages.getString("postman.topmenu.import.tooltip"));
            menuImportPostmanCollection.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame());
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuImportPostmanCollection;
    }

    @Override
    public void unload() {
        super.unload();

        if (importDialog != null) {
            importDialog.dispose();
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("postman.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("postman.desc");
    }

    private CommandLineArgument[] getCommandLineArguments() {
        CommandLineArgument[] args = new CommandLineArgument[3];
        args[ARG_IMPORT_FILE_IDX] =
                new CommandLineArgument(
                        "-postmanfile",
                        1,
                        null,
                        "",
                        "-postmanfile <path>          "
                                + Constant.messages.getString("postman.cmdline.file.help"));
        args[ARG_IMPORT_URL_IDX] =
                new CommandLineArgument(
                        "-postmanurl",
                        1,
                        null,
                        "",
                        "-postmanurl <url>            "
                                + Constant.messages.getString("postman.cmdline.url.help"));
        args[ARG_ENDPOINT_URL_IDX] =
                new CommandLineArgument(
                        "-postmanendpointurl",
                        1,
                        null,
                        "",
                        "-postmanendpointurl <url>    "
                                + Constant.messages.getString("postman.cmdline.endpointurl.help"));
        return args;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        // TODO: Implement importing
        if (args[ARG_IMPORT_FILE_IDX].isEnabled()) {
            CommandLine.info("This is currently under development and is not yet available.");
        }
        if (args[ARG_IMPORT_URL_IDX].isEnabled()) {
            CommandLine.info("This is currently under development and is not yet available.");
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
            if (importDialog != null) {
                importDialog.clearFields();
            }
        }

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}
    }
}
