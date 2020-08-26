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
package org.zaproxy.addon.har;

import edu.umass.cs.benchlab.har.tools.HarFileReader;
import java.awt.EventQueue;
import java.io.File;
import java.io.IOException;
import java.util.List;
import javax.swing.JFileChooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

public class ExtensionHar extends ExtensionAdaptor {

    private static final String NAME = "ExtensionHar";
    private static final String THREAD_PREFIX = "ZAP-Import-Har-";
    private static final Logger LOG = LogManager.getLogger(ExtensionHar.class);

    private int threadId = 1;

    public ExtensionHar() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuImportHar());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuItemSaveHarMessage());
        }

        extensionHook.addApiImplementor(new HarAPI(this));
    }

    private ZapMenuItem getMenuImportHar() {
        ZapMenuItem result = new ZapMenuItem("har.topmenu.import.importhar");
        result.setToolTipText(Constant.messages.getString("har.topmenu.import.importhar.tooltip"));
        result.addActionListener(
                e -> {
                    JFileChooser chooser =
                            new JFileChooser(
                                    Model.getSingleton().getOptionsParam().getUserDirectory());
                    int rc = chooser.showOpenDialog(View.getSingleton().getMainFrame());
                    if (rc == JFileChooser.APPROVE_OPTION) {

                        Thread t =
                                new Thread() {
                                    @Override
                                    public void run() {
                                        this.setName(THREAD_PREFIX + threadId++);
                                        importHarFileImpl(chooser.getSelectedFile());
                                    }
                                };
                        t.start();
                    }
                });
        return result;
    }

    private void importHarFileImpl(File file) {
        try {
            importHarFile(file);
        } catch (IOException e) {
            LOG.error(e);
            View.getSingleton()
                    .showWarningDialog(
                            Constant.messages.getString(
                                    "har.file.import.error", file.getAbsolutePath()));
        }
    }

    public void importHarFile(File file) throws IOException {
        List<HttpMessage> messages =
                HarImporter.getHttpMessages(new HarFileReader().readHarFile(file));
        messages.forEach(ExtensionHar::persistMessage);
    }

    private static void persistMessage(HttpMessage message) {
        HistoryReference historyRef;

        if (message.getHistoryRef() == null) {
            try {
                historyRef =
                        new HistoryReference(
                                Model.getSingleton().getSession(),
                                HistoryReference.TYPE_ZAP_USER,
                                message);
            } catch (Exception e) {
                LOG.warn(e.getMessage(), e);
                return;
            }
        } else {
            historyRef = message.getHistoryRef();
        }

        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        if (extHistory != null) {
            EventQueue.invokeLater(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton()
                                .getSession()
                                .getSiteTree()
                                .addPath(historyRef, message);
                    });
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
