/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.exim.urls;

import java.awt.EventQueue;
import java.io.BufferedReader;
import java.io.File;
import java.nio.file.Files;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;

public final class UrlsImporter {

    private static final Logger LOG = LogManager.getLogger(UrlsImporter.class);

    private UrlsImporter() {}

    public static boolean importUrlFile(File file) {
        if (file == null) {
            return false;
        }
        try (BufferedReader in = Files.newBufferedReader(file.toPath())) {
            if (View.isInitialised()) {
                View.getSingleton().getOutputPanel().setTabFocus();
            }

            HttpSender sender =
                    new HttpSender(
                            Model.getSingleton().getOptionsParam().getConnectionParam(),
                            true,
                            HttpSender.MANUAL_REQUEST_INITIATOR);

            String line;
            StringBuilder outputLine = new StringBuilder();
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("#") && line.trim().length() > 0) {
                    try {
                        outputLine
                                .append(HttpRequestHeader.GET)
                                .append('\t')
                                .append(line)
                                .append('\t');
                        HttpMessage msg = new HttpMessage(new URI(line, false));
                        sender.sendAndReceive(msg, true);
                        persistMessage(msg);

                        outputLine.append(msg.getResponseHeader().getStatusCode());

                    } catch (Exception e) {
                        outputLine.append(e.getMessage());
                    }
                    outputLine.append('\n');
                    if (View.isInitialised()) {
                        EventQueue.invokeLater(
                                () -> {
                                    View.getSingleton()
                                            .getOutputPanel()
                                            .append(outputLine.toString());
                                    outputLine.delete(0, outputLine.length());
                                });
                    }
                }
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return false;
        }
        return true;
    }

    private static void persistMessage(HttpMessage message) {
        HistoryReference historyRef;

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
}
