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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
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
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class HarImporter {

    private static final Logger LOGGER = LogManager.getLogger(HarImporter.class);
    private static final String STATS_HAR_FILE = "import.har.file";
    private static final String STATS_HAR_FILE_MSG = "import.har.file.message";
    private static final String STATS_HAR_FILE_MSG_ERROR = "import.har.file.message.errors";
    // The following list is ordered to hopefully match quickly
    private static final List<String> ACCEPTED_VERSIONS =
            List.of(
                    HttpHeader.HTTP11,
                    HttpHeader.HTTP2,
                    "http/2.0",
                    HttpHeader.HTTP10,
                    "h3",
                    "http/3",
                    "http/3.0",
                    HttpHeader.HTTP09);
    private static final Predicate<String> CHECK_MISSING =
            vers -> vers == null || vers.isEmpty() || vers.equalsIgnoreCase(HttpHeader.HTTP);
    private static final Predicate<String> CHECK_H3 =
            vers ->
                    vers.equalsIgnoreCase("h3")
                            || vers.equalsIgnoreCase("http/3")
                            || vers.equalsIgnoreCase("http/3.0");

    protected static final String STATS_HAR_FILE_ERROR = "import.har.file.errors";

    private static ExtensionHistory extHistory;

    private ProgressPaneListener progressListener;
    private boolean success;

    public HarImporter(File file) {
        this(file, null);
    }

    public HarImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        HarLog log = null;
        try {
            log = new HarReader().readFromFile(file).getLog();
            importHarLog(log);
        } catch (HarReaderException e) {
            LOGGER.warn("Failed to read HAR file: {}\n{}", file.getAbsolutePath(), e.getMessage());
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_ERROR);
            success = false;
            completed();
            return;
        }
        completed();
    }

    public HarImporter(HarLog harLog, ProgressPaneListener listener) {
        this.progressListener = listener;
        importHarLog(harLog);
        completed();
    }

    private void importHarLog(HarLog log) {
        processMessages(log);
        Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE);
        success = true;
    }

    private void processMessages(HarLog log) {
        if (log == null) {
            return;
        }

        List<HttpMessage> messages = null;

        try {
            messages = getHttpMessages(log);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.warn("Failed to process HAR entries. {}", e.getMessage());
            LOGGER.debug(e, e);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_HAR_FILE_ERROR);
            completed();
            return;
        }
        int count = 0;
        for (HttpMessage msg : messages) {
            if (msg == null) {
                updateProgress(
                        ++count, Constant.messages.getString("exim.progress.invalidmessage"));
                continue;
            }
            persistMessage(msg);
            updateProgress(++count, msg.getRequestHeader().getURI().toString());
        }
    }

    private static HarLog preProcessHarLog(HarLog log) {
        List<HarEntry> entries =
                log.getEntries().stream()
                        .filter(HarImporter::entryIsNotLocalPrivate)
                        .filter(HarImporter::entryHasUsableHttpVersion)
                        .collect(Collectors.toList());
        log.setEntries(entries);
        return log;
    }

    private static boolean entryHasUsableHttpVersion(HarEntry entry) {
        // Handle missing httpVersion (set http/1.1)
        preProcessHttpVersion(
                entry,
                CHECK_MISSING.test(entry.getRequest().getHttpVersion()),
                HttpHeader.HTTP11,
                false);
        preProcessHttpVersion(
                entry,
                CHECK_MISSING.test(entry.getResponse().getHttpVersion()),
                HttpHeader.HTTP11,
                true);
        // Handle http/3 (set http/2)
        preProcessHttpVersion(
                entry, CHECK_H3.test(entry.getRequest().getHttpVersion()), HttpHeader.HTTP2, false);
        preProcessHttpVersion(
                entry, CHECK_H3.test(entry.getResponse().getHttpVersion()), HttpHeader.HTTP2, true);

        if (!containsIgnoreCase(ACCEPTED_VERSIONS, entry.getRequest().getHttpVersion())
                || !containsIgnoreCase(ACCEPTED_VERSIONS, entry.getResponse().getHttpVersion())) {
            LOGGER.warn(
                    "Message with unsupported HTTP version (Req version: {}, Resp version: {}) will be dropped: {}",
                    entry.getRequest().getHttpVersion(),
                    entry.getResponse().getHttpVersion(),
                    entry.getRequest().getUrl());
            return false;
        }
        return true;
    }

    private static boolean entryIsNotLocalPrivate(HarEntry entry) {
        String url = entry.getRequest().getUrl();
        if (StringUtils.startsWithIgnoreCase(url, "about")
                || StringUtils.startsWithIgnoreCase(url, "chrome")
                || StringUtils.startsWithIgnoreCase(url, "edge")) {
            LOGGER.debug("Skipping local private entry: {}", url);
            return false;
        }
        return true;
    }

    protected static List<HttpMessage> getHttpMessages(HarLog log)
            throws HttpMalformedHeaderException {
        preProcessHarLog(log);

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
                .append(HttpHeader.CRLF);

        for (HarHeader harHeader : harResponse.getHeaders()) {
            String value = harHeader.getValue();
            if (value.contains("\n") || value.contains("\r")) {
                LOGGER.info(
                        "{}\n\t{} value contains CR or LF and is likely invalid (though it may have been successfully set to the message):\n\t{}",
                        message.getRequestHeader().getURI(),
                        harHeader.getName(),
                        StringEscapeUtils.escapeJava(value));
            }
            strBuilderResHeader
                    .append(harHeader.getName())
                    .append(": ")
                    .append(harHeader.getValue())
                    .append(HttpHeader.CRLF);
        }
        strBuilderResHeader.append(HttpHeader.CRLF);

        HarContent harContent = harResponse.getContent();
        try {
            message.setResponseHeader(new HttpResponseHeader(strBuilderResHeader.toString()));
        } catch (HttpMalformedHeaderException he) {
            LOGGER.info(
                    "Couldn't set response header for: {}", message.getRequestHeader().getURI());
        }
        message.setResponseFromTargetHost(true);
        if (harContent != null) {
            if ("base64".equals(harContent.getEncoding())) {
                var text = harContent.getText();
                if (text != null)
                    try {
                        message.setResponseBody(Base64.getDecoder().decode(text));
                    } catch (IllegalArgumentException e) {
                        LOGGER.debug(
                                "Failed to base64 decode body {}. Setting as plain text.", text, e);
                        message.setResponseBody(text);
                    }
            } else {
                message.setResponseBody(harContent.getText());
            }
        }
    }

    private static boolean containsIgnoreCase(List<String> checkList, String candidate) {
        return checkList.stream().anyMatch(e -> e.equalsIgnoreCase(candidate));
    }

    private static void preProcessHttpVersion(
            HarEntry entry, boolean condition, String vers, boolean response) {
        if (condition) {
            if (response) {
                entry.getResponse().setHttpVersion(vers);
            } else {
                entry.getRequest().setHttpVersion(vers);
            }
            LOGGER.info(
                    "Setting {} version to {} for {}",
                    response ? "response" : "request",
                    response
                            ? entry.getResponse().getHttpVersion()
                            : entry.getRequest().getHttpVersion(),
                    entry.getRequest().getUrl());
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
