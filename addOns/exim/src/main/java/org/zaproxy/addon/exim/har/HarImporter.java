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
package org.zaproxy.addon.exim.har;

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.HarContent;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarHeader;
import de.sstoehr.harreader.model.HarLog;
import de.sstoehr.harreader.model.HarResponse;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class HarImporter {

    private static final Logger LOGGER = LogManager.getLogger(HarImporter.class);
    private static final String STATS_HAR_FILE = "import.har.file";
    private static final String STATS_HAR_FILE_MSG = "import.har.file.message";
    private static final String STATS_HAR_FILE_MSG_ERROR = "import.har.file.message.errors";
    protected static final String STATS_HAR_FILE_ERROR = "import.har.file.errors";

    private ProgressPaneListener progressListener;
    private boolean success;
    private static ExtensionHistory extHistory;

    public HarImporter(File file) {
        this(file, null);
    }

    public HarImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        HarLog log = null;
        try {
            log = new HarReader().readFromFile(file).getLog();
        } catch (HarReaderException e) {
            LOGGER.warn(
                    "Failed to read HAR file: {} \n {}", file.getAbsolutePath(), e.getMessage());
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_ERROR);
            success = false;
            completed();
            return;
        }
        importHarFile(log);
        completed();
    }

    public HarImporter(HarLog harLog, ProgressPaneListener listener) {
        this.progressListener = listener;
        importHarFile(harLog);
        completed();
    }

    static List<HttpMessage> getHttpMessages(HarLog log) throws HttpMalformedHeaderException {
        List<HttpMessage> result = new ArrayList<>();
        List<HarEntry> entries = log.getEntries();
        for (HarEntry entry : entries) {
            result.add(getHttpMessage(entry));
        }
        return result;
    }

    private static HttpMessage getHttpMessage(HarEntry harEntry)
            throws HttpMalformedHeaderException {
        HttpMessage result = HarUtils.createHttpMessage(harEntry.getRequest());
        setHttpResponse(harEntry.getResponse(), result);
        return result;
    }

    private static void setHttpResponse(HarResponse harResponse, HttpMessage message)
            throws HttpMalformedHeaderException {
        StringBuilder strBuilderResHeader = new StringBuilder();

        // empty responses without status code are possible
        if (harResponse.getStatus() == 0) {
            return;
        }

        strBuilderResHeader
                .append(harResponse.getHttpVersion())
                .append(' ')
                .append(harResponse.getStatus())
                .append(' ')
                .append(harResponse.getStatusText())
                .append("\r\n");

        for (HarHeader harHeader : harResponse.getHeaders()) {
            strBuilderResHeader
                    .append(harHeader.getName())
                    .append(": ")
                    .append(harHeader.getValue())
                    .append("\r\n");
        }
        strBuilderResHeader.append("\r\n");

        HarContent harContent = harResponse.getContent();
        message.setResponseHeader(new HttpResponseHeader(strBuilderResHeader.toString()));
        message.setResponseFromTargetHost(true);
        if (harContent != null) {
            message.setResponseBody(new HttpResponseBody(harContent.getText()));
        }
    }

    private void importHarFile(HarLog log) {
        try {
            processMessages(log);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE);
            success = true;
        } catch (IOException e) {
            LOGGER.warn(
                    Constant.messages.getString(ExtensionExim.EXIM_OUTPUT_ERROR, e.getMessage()));
            LOGGER.warn(e);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_ERROR);
            success = false;
        }
    }

    private HarLog preProcessHarLog(HarLog log) {
        List<HarEntry> h3ForRemoval = new ArrayList<>();
        List<HarEntry> localPrivate = new ArrayList<>();
        log.getEntries().stream()
                .forEach(entry -> preProcessHarEntry(h3ForRemoval, localPrivate, entry));
        log.getEntries().removeAll(h3ForRemoval);
        log.getEntries().removeAll(localPrivate);
        int adjustment = h3ForRemoval.size() + localPrivate.size();
        updateProgress(adjustment, "");
        return log;
    }

    private void preProcessHarEntry(
            List<HarEntry> h3ForRemoval, List<HarEntry> localPrivate, HarEntry entry) {
        String vers = entry.getRequest().getHttpVersion();
        preProcessH3Entries(h3ForRemoval, entry, vers);

        String url = entry.getRequest().getUrl();
        preProcessLocalPrivateEntries(localPrivate, entry, url);

        // No point processing version or headers on entries being dropped
        if (!localPrivate.contains(entry) && !h3ForRemoval.contains(entry)) {
            preProcessEntryHttpVersion(entry, vers, false);
            preProcessEntryHttpVersion(entry, entry.getResponse().getHttpVersion(), true);
            entry.getResponse().getHeaders().forEach(this::preProcessHarHeaders);
        }
    }

    private void preProcessH3Entries(List<HarEntry> h3ForRemoval, HarEntry entry, String vers) {
        if (vers != null
                && (entry.getRequest().getHttpVersion().equalsIgnoreCase("h3")
                        || entry.getResponse().getHttpVersion().equalsIgnoreCase("h3"))) {
            h3ForRemoval.add(entry);
            LOGGER.warn(
                    "Unsupported HTTP/3 (h3) message will be dropped: {}",
                    entry.getRequest().getUrl());
        }
    }

    private void preProcessLocalPrivateEntries(
            List<HarEntry> localPrivate, HarEntry entry, String url) {
        if (StringUtils.startsWithIgnoreCase(url, "about")
                || StringUtils.startsWithIgnoreCase(url, "chrome")
                || StringUtils.startsWithIgnoreCase(url, "edge")) {
            localPrivate.add(entry);
            LOGGER.debug("Skipping local private entry: {}", url);
        }
    }

    private void preProcessEntryHttpVersion(HarEntry entry, String vers, boolean isResponse) {
        if (vers == null || vers.isEmpty() || vers.equalsIgnoreCase(HttpHeader.HTTP)) {
            if (isResponse) {
                entry.getResponse().setHttpVersion(HttpHeader.HTTP11);
            } else {
                entry.getRequest().setHttpVersion(HttpHeader.HTTP11);
            }
            LOGGER.debug(
                    "Setting {} version to {} for {}",
                    isResponse ? "repsonse" : "request",
                    isResponse
                            ? entry.getResponse().getHttpVersion()
                            : entry.getRequest().getHttpVersion(),
                    entry.getRequest().getUrl());
        }
    }

    private void preProcessHarHeaders(HarHeader header) {
        String name = header.getName();
        String value = header.getValue();
        if ((name.equalsIgnoreCase(HttpFieldsNames.CACHE_CONTROL)
                        || name.equalsIgnoreCase(HttpFieldsNames.SET_COOKIE))
                && (value.contains("\n") || value.contains("\r"))) {
            header.setValue(header.getValue().replaceAll("[\r\n]", ", "));
            // Escaped so the CRLF actually show
            LOGGER.debug(
                    "Removed CRLF from \"{}\" header value: {}",
                    name,
                    StringEscapeUtils.escapeJava(value));
        }
    }

    private void processMessages(HarLog log) throws IOException {
        List<HttpMessage> messages = null;
        if (log == null) {
            return;
        }
        preProcessHarLog(log);
        try {
            messages = HarImporter.getHttpMessages(log);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.warn("Failed to process HAR entries. {}", e.getMessage());
            LOGGER.debug(e, e);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_ERROR);
            completed();
            return;
        }
        int count = progressListener != null ? progressListener.getTasksDone() : 0;
        for (HttpMessage msg : messages) {
            if (msg == null) {
                continue;
            }
            persistMessage(msg);
            updateProgress(++count, msg.getRequestHeader().getURI().toString());
        }
    }

    private static void persistMessage(HttpMessage message) {
        HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_MSG);
        } catch (Exception e) {
            LOGGER.warn(e.getMessage());
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_MSG_ERROR);
            return;
        }

        if (getExtensionHistory() != null) {
            ThreadUtils.invokeAndWaitHandled(() -> addMessage(historyRef, message));
        }
    }

    private static ExtensionHistory getExtensionHistory() {
        if (extHistory == null) {
            extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return extHistory;
    }

    private static void addMessage(HistoryReference historyRef, HttpMessage message) {
        getExtensionHistory().addHistory(historyRef);
        Model.getSingleton().getSession().getSiteTree().addPath(historyRef, message);
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
