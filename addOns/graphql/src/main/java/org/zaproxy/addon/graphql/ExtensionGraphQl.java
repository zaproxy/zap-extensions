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
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionGraphQl extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionGraphQl";

    private ZapMenuItem menuImportLocalGraphQl = null;
    private ZapMenuItem menuImportUrlGraphQl = null;

    private CommandLineArgument[] arguments = new CommandLineArgument[3];
    private static final int ARG_IMPORT_FILE_IDX = 0;
    private static final int ARG_IMPORT_URL_IDX = 1;
    private static final int ARG_END_URL_IDX = 2;

    public ExtensionGraphQl() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportLocalGraphQl());
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrlGraphQl());
        }

        extensionHook.addApiImplementor(new GraphQlApi(this));
        extensionHook.addCommandLine(getCommandLineArguments());
    }

    /* Menu option to import a local GraphQl file. */
    private ZapMenuItem getMenuImportLocalGraphQl() {
        if (menuImportLocalGraphQl == null) {
            menuImportLocalGraphQl = new ZapMenuItem("graphql.topmenu.import.importgraphql");
            menuImportLocalGraphQl.setToolTipText(
                    Constant.messages.getString("graphql.topmenu.import.importgraphql.tooltip"));
            menuImportLocalGraphQl.addActionListener(
                    e -> new ImportFromFileDialog(View.getSingleton().getMainFrame(), this));
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
                    e -> new ImportFromUrlDialog(View.getSingleton().getMainFrame(), this));
        }
        return menuImportUrlGraphQl;
    }

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
        arguments[ARG_IMPORT_FILE_IDX] =
                new CommandLineArgument(
                        "-graphqlfile",
                        1,
                        null,
                        "",
                        "-graphqlfile <path>      "
                                + Constant.messages.getString("graphql.cmdline.file.help"));
        arguments[ARG_IMPORT_URL_IDX] =
                new CommandLineArgument(
                        "-graphqlurl",
                        1,
                        null,
                        "",
                        "-graphqlurl <url>        "
                                + Constant.messages.getString("graphql.cmdline.url.help"));
        arguments[ARG_END_URL_IDX] =
                new CommandLineArgument(
                        "-graphqlendurl",
                        1,
                        null,
                        "",
                        "-graphqlendurl <url>  "
                                + Constant.messages.getString("graphql.cmdline.endurl.help"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        if (arguments[ARG_IMPORT_FILE_IDX].isEnabled()) {
            System.out.println("Nothing to see here (yet) :)");
        }
        if (arguments[ARG_IMPORT_URL_IDX].isEnabled()) {
            System.out.println("Nothing to see here (yet) :)");
        }
        if (arguments[ARG_END_URL_IDX].isEnabled()) {
            System.out.println("Nothing to see here (yet) :)");
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
