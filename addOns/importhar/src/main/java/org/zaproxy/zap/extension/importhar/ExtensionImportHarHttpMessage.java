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
package org.zaproxy.zap.extension.importhar;

import edu.umass.cs.benchlab.har.tools.HarFileReader;
import java.awt.EventQueue;
import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import javax.swing.JFileChooser;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportHarHttpMessage extends ExtensionAdaptor {

    private static final String NAME = "ExtensionImportHarHttpMessage";

    private static final String THREAD_PREFIX = "ZAP-Import-Har-";

    private static Logger log = Logger.getLogger(ExtensionImportHarHttpMessage.class);
    private int threadId = 1;

    public ExtensionImportHarHttpMessage() {
        super(NAME);
        setI18nPrefix("importhar");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportHar());
        }

        extensionHook.addApiImplementor(new ImportHarAPI(this));
    }

    private ZapMenuItem getMenuImportHar() {
        ZapMenuItem result = new ZapMenuItem("savehar.topmenu.import.importhar");
        result.setToolTipText(
                Constant.messages.getString("savehar.topmenu.import.importhar.tooltip"));
        result.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        // Prompt for a file
                        final JFileChooser chooser =
                                new JFileChooser(
                                        Model.getSingleton().getOptionsParam().getUserDirectory());
                        int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                        if (rc == JFileChooser.APPROVE_OPTION) {

                            Thread t =
                                    new Thread() {
                                        @Override
                                        public void run() {
                                            this.setName(THREAD_PREFIX + threadId++);
                                            _importHarFile(chooser.getSelectedFile());
                                        }
                                    };
                            t.start();
                        }
                    }
                });
        return result;
    }

    private void _importHarFile(File file) {
        String ERROR_IMPORT = Constant.messages.getString("importhar.file.import.error");
        try {
            importHarFile(file);
        } catch (IOException e) {
            log.error(e);
            View.getSingleton()
                    .showWarningDialog(MessageFormat.format(ERROR_IMPORT, file.getAbsolutePath()));
        }
    }

    public void importHarFile(File file) throws IOException {
        List<HttpMessage> messages =
                HarImporter.getHttpMessages(new HarFileReader().readHarFile(file));
        messages.forEach(message -> persistMessage(message));
    }

    private static void persistMessage(final HttpMessage message) {
        // Add the message to the history panel and sites tree
        final HistoryReference historyRef;

        if (message.getHistoryRef() == null) {
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
        } else {
            historyRef = message.getHistoryRef();
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
}
