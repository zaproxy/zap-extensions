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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.Stats;

public final class UrlsImporter {

    private static final Logger LOG = LogManager.getLogger(UrlsImporter.class);
    private static final String STATS_URL_FILE = "import.url.file";
    private static final String STATS_URL_FILE_ERROR = "import.url.file.errors";
    private static final String STATS_URL_FILE_URL = "import.url.file.url";
    private static final String STATS_URL_FILE_URL_ERROR = "import.url.file.url.errors";

    private UrlsImporter() {}

    public static boolean importUrlFile(File file) {
        if (file == null) {
            return false;
        }
        try (BufferedReader in = Files.newBufferedReader(file.toPath())) {
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE);
            if (View.isInitialised()) {
                View.getSingleton().getOutputPanel().setTabFocus();
            }
            ExtensionExim.updateOutput("exim.output.start", file.toPath().toString());

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
                        Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_URL);

                    } catch (Exception e) {
                        outputLine.append(e.getMessage());
                        Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_URL_ERROR);
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
            ExtensionExim.updateOutput("exim.output.end", file.toPath().toString());
        } catch (Exception e) {
            LOG.warn(
                    Constant.messages.getString(
                            ExtensionExim.EXIM_OUTPUT_ERROR, file.getAbsoluteFile()));
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_ERROR);
            ExtensionExim.updateOutput(ExtensionExim.EXIM_OUTPUT_ERROR, file.toPath().toString());
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
            LOG.warn(e.getMessage());
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
