/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.importurls;

import java.awt.EventQueue;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import javax.swing.JFileChooser;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportUrls extends ExtensionAdaptor {

    public static final String NAME = "ExtensionImportUrls";

    private static final String THREAD_PREFIX = "ZAP-Import-Urls-";

    private ZapMenuItem menuImportUrls;
    private int threadId = 1;

    private ImportUrlsAPI api;

    private static Logger log = Logger.getLogger(ExtensionImportUrls.class);

    public ExtensionImportUrls() {
        super(NAME);
        this.setOrder(157);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportUrls());
        }

        this.api = new ImportUrlsAPI(this);
        extensionHook.addApiImplementor(api);
    }

    private ZapMenuItem getMenuImportUrls() {
        if (menuImportUrls == null) {
            menuImportUrls =
                    new ZapMenuItem(
                            "importurls.topmenu.import.importurls",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_I, 0, false));
            menuImportUrls.setToolTipText(
                    Constant.messages.getString("importurls.topmenu.import.importurls.tooltip"));

            menuImportUrls.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            // Prompt for a file
                            final JFileChooser chooser =
                                    new JFileChooser(
                                            Model.getSingleton()
                                                    .getOptionsParam()
                                                    .getUserDirectory());
                            int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                            if (rc == JFileChooser.APPROVE_OPTION) {

                                Thread t =
                                        new Thread() {
                                            @Override
                                            public void run() {
                                                this.setName(THREAD_PREFIX + threadId++);
                                                importUrlFile(chooser.getSelectedFile());
                                            }
                                        };
                                t.start();
                            }
                        }
                    });
        }
        return menuImportUrls;
    }

    public String importUrlFile(File file) {
        if (file == null) {
            return "";
        }
        BufferedReader in = null;
        try {
            if (View.isInitialised()) {
                // Switch to the output panel, if in GUI mode
                View.getSingleton().getOutputPanel().setTabFocus();
            }
            in = new BufferedReader(new FileReader(file));

            HttpSender sender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.MANUAL_REQUEST_INITIATOR);

            String line;
            StringBuilder outputLine;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("#") && line.trim().length() > 0) {
                    if (!line.startsWith("http")) {
                        // ZAP exports urls to a file in which each line starts with the HTTP Method
                        // (verb)
                        // followed by a tab, so makes sense to cope with it.
                        // Otherwise assume complete URLs starting with http(s) scheme.
                        int tabIdx = line.indexOf("\t");
                        if (tabIdx > -1) {
                            line = line.substring(line.indexOf("\t")).trim();
                        }
                    }
                    outputLine = new StringBuilder();
                    try {
                        outputLine.append("GET").append("\t").append(line).append("\t");
                        HttpMessage msg = new HttpMessage(new URI(line, false));
                        sender.sendAndReceive(msg, true);
                        persistMessage(msg);

                        outputLine.append(msg.getResponseHeader().getStatusCode());

                    } catch (Exception e) {
                        outputLine.append(e.getMessage());
                    }
                    outputLine.append("\n");
                    if (View.isInitialised()) {
                        final String str = outputLine.toString();
                        EventQueue.invokeLater(
                                new Runnable() {
                                    @Override
                                    public void run() {
                                        View.getSingleton().getOutputPanel().append(str);
                                    }
                                });
                    }
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
        return null;
    }

    private static void persistMessage(final HttpMessage message) {
        // Add the message to the history panel and sites tree
        final HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
        } catch (Exception e) {
            log.warn(e.getMessage(), e);
            return;
        }

        final ExtensionHistory extHistory =
                (ExtensionHistory)
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionHistory.NAME);
        if (extHistory != null) {
            EventQueue.invokeLater(
                    new Runnable() {
                        @Override
                        public void run() {
                            extHistory.addHistory(historyRef);
                            Model.getSingleton()
                                    .getSession()
                                    .getSiteTree()
                                    .addPath(historyRef, message);
                        }
                    });
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("importurls.desc");
    }
}
