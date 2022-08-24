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
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.Stats;

public class UrlsImporter {

    private static final Logger LOG = LogManager.getLogger(UrlsImporter.class);
    private static final String STATS_URL_FILE = "import.url.file";
    private static final String STATS_URL_FILE_ERROR = "import.url.file.errors";
    private static final String STATS_URL_FILE_URL = "import.url.file.url";
    private static final String STATS_URL_FILE_URL_ERROR = "import.url.file.url.errors";

    private final HttpSender sender =
            new HttpSender(
                    Model.getSingleton().getOptionsParam().getConnectionParam(),
                    true,
                    HttpSender.MANUAL_REQUEST_INITIATOR);
    private ProgressPaneListener progressListener;
    private boolean success;

    public UrlsImporter(File file) {
        this(file, null);
    }

    public UrlsImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        importUrlFile(file);
        completed();
    }

    private void importUrlFile(File file) {
        if (file == null) {
            success = false;
            return;
        }
        try (BufferedReader in = Files.newBufferedReader(file.toPath())) {
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE);
            ExtensionExim.updateOutput("exim.output.start", file.toPath().toString());

            int count = 1;
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("#") && line.trim().length() > 0) {
                    updateProgress(count, line);
                    processLine(line);
                    count++;
                }
            }
            ExtensionExim.updateOutput("exim.output.end", file.toPath().toString());
        } catch (Exception e) {
            LOG.warn(
                    Constant.messages.getString(
                            ExtensionExim.EXIM_OUTPUT_ERROR, file.getAbsoluteFile()));
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_ERROR);
            ExtensionExim.updateOutput(ExtensionExim.EXIM_OUTPUT_ERROR, file.toPath().toString());
            success = false;
            return;
        }
        success = true;
    }

    private void processLine(String line) {
        StringBuilder outputLine = new StringBuilder();
        outputLine.append(HttpRequestHeader.GET).append('\t').append(line).append('\t');
        outputLine.append(processRequest(line));
        outputLine.append('\n');
        if (View.isInitialised()) {
            EventQueue.invokeLater(
                    () -> {
                        View.getSingleton().getOutputPanel().append(outputLine.toString());
                        outputLine.delete(0, outputLine.length());
                    });
        }
    }

    private String processRequest(String line) {
        try {
            URI url = new URI(line, false);
            if (hasSheme(url)) {
                HttpMessage msg = new HttpMessage(url);
                sender.sendAndReceive(msg, true);
                persistMessage(msg);

                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_URL);
                return String.valueOf(msg.getResponseHeader().getStatusCode());
            }
            return handleWarning(Constant.messages.getString("exim.importurls.warn.scheme", line));
        } catch (Exception e) {
            return handleWarning(e.getMessage());
        }
    }

    private static String handleWarning(String message) {
        LOG.warn(message);
        Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_URL_FILE_URL_ERROR);
        return message;
    }

    private static boolean hasSheme(URI url) {
        return url.getScheme() != null;
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

    public boolean isSuccess() {
        return success;
    }

    private void updateProgress(int count, String line) {
        if (progressListener != null) {
            progressListener.setTasksDone(count);
            progressListener.setCurrentTask(
                    Constant.messages.getString("exim.progress.currentimport", line));
        }
    }

    private void completed() {
        if (progressListener != null) {
            progressListener.completed();
        }
    }
}
