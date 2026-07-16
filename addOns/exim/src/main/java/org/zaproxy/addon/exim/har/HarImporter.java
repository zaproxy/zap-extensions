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
import de.sstoehr.harreader.model.Har;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarEntry.HarEntryBuilder;
import de.sstoehr.harreader.model.HarLog;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.Strings;
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
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class HarImporter {

    private static final Logger LOGGER = LogManager.getLogger(HarImporter.class);
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

    private static final String STATS_HAR = ExtensionExim.STATS_PREFIX + "import.har.%s";

    enum DataSource {
        FILE("file"),
        STRING("string");

        private final String type;

        DataSource(String type) {
            this.type = type;
        }

        void successful() {
            incCounter(STATS_HAR);
        }

        void messageSuccessful() {
            incCounter(STATS_HAR + ".message");
        }

        void messageError() {
            incCounter(STATS_HAR + ".message.errors");
        }

        void error() {
            incCounter(STATS_HAR + ".errors");
        }

        private void incCounter(String key) {
            Stats.incCounter(key.formatted(type));
        }
    }

    private static ExtensionHistory extHistory;

    private final DataSource dataSource;
    private final boolean sendRequests;
    private ProgressPaneListener progressListener;
    private SendContext sendContext;
    private boolean success;

    public HarImporter(String data) {
        this(data, false);
    }

    public HarImporter(String data, boolean sendRequests) {
        this.dataSource = DataSource.STRING;
        this.sendRequests = sendRequests;
        importData(reader -> reader.readFromString(data));
    }

    public HarImporter(File file) {
        this(file, null, false);
    }

    public HarImporter(File file, ProgressPaneListener listener) {
        this(file, listener, false);
    }

    public HarImporter(File file, ProgressPaneListener listener, boolean sendRequests) {
        dataSource = DataSource.FILE;
        this.progressListener = listener;
        this.sendRequests = sendRequests;
        importData(reader -> reader.readFromFile(file));
    }

    private void importData(HarProvider provider) {
        try {
            HarLog log = provider.from(new HarReader()).log();
            importHarLog(log);
        } catch (HarReaderException e) {
            LOGGER.warn("Failed to read HAR data: {}", e.getMessage());
            dataSource.error();
            success = false;
        } finally {
            completed();
        }
    }

    public HarImporter(HarLog harLog, ProgressPaneListener listener) {
        this(harLog, listener, false);
    }

    public HarImporter(HarLog harLog, ProgressPaneListener listener, boolean sendRequests) {
        dataSource = DataSource.FILE;
        this.progressListener = listener;
        this.sendRequests = sendRequests;
        importHarLog(harLog);
        completed();
    }

    private void importHarLog(HarLog log) {
        processMessages(log);
        dataSource.successful();
        success = true;
    }

    private SendContext getSendContext() {
        if (sendContext == null) {
            sendContext = SendContext.create();
        }
        return sendContext;
    }

    private void processMessages(HarLog log) {
        if (log == null) {
            return;
        }

        List<HarEntry> entries = preProcessHarEntries(log, sendRequests);
        int count = 0;
        for (HarEntry entry : entries) {
            HttpMessage msg = sendRequests ? getSendContext().send(entry) : getHttpMessage(entry);
            if (msg == null) {
                updateProgress(
                        ++count, Constant.messages.getString("exim.progress.invalidmessage"));
                continue;
            }
            persistMessage(msg);
            updateProgress(++count, msg.getRequestHeader().getURI().toString());
        }
    }

    private static HttpRequestConfig createRequestConfig(AtomicBoolean requestValid) {
        return HttpRequestConfig.builder()
                .setRedirectionValidator(
                        new HttpRedirectionValidator() {
                            @Override
                            public void notifyMessageReceived(HttpMessage msg) {}

                            @Override
                            public boolean isValid(URI redirection) {
                                requestValid.set(isValidForCurrentMode(redirection));
                                return requestValid.get();
                            }
                        })
                .build();
    }

    record SendContext(HttpSender sender, HttpRequestConfig config, AtomicBoolean requestValid) {

        static SendContext create() {
            AtomicBoolean requestValid = new AtomicBoolean(true);
            return new SendContext(
                    new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR),
                    createRequestConfig(requestValid),
                    requestValid);
        }

        HttpMessage send(HarEntry entry) {
            try {
                HttpMessage message = HarUtils.createHttpMessage(entry.request());
                URI uri = message.getRequestHeader().getURI();
                if (!isValidForCurrentMode(uri)) {
                    return null;
                }
                requestValid.set(true);
                sender.sendAndReceive(message, config);
                if (!requestValid.get()) {
                    return null;
                }
                return message;
            } catch (IOException e) {
                LOGGER.warn("Failed to send HAR request: {}", e.getMessage());
                LOGGER.debug(e, e);
                return null;
            }
        }
    }

    /**
     * Tells whether or not the given {@code uri} is valid for the current {@link Control.Mode}.
     *
     * <p>Not valid in {@code safe} mode, or in {@code protect} mode when out of scope.
     */
    private static boolean isValidForCurrentMode(URI uri) {
        return switch (Control.getSingleton().getMode()) {
            case safe -> false;
            case protect -> Model.getSingleton().getSession().isInScope(uri.toString());
            default -> true;
        };
    }

    private static List<HarEntry> preProcessHarEntries(HarLog log, boolean sendRequests) {
        return log.entries().stream()
                .filter(HarImporter::entryIsNotLocalPrivate)
                .map(HarImporter::correctHttpVersions)
                .filter(entry -> entryHasUsableHttpVersion(entry, sendRequests))
                .toList();
    }

    private static boolean entryHasUsableHttpVersion(HarEntry entry, boolean sendRequests) {
        if (!containsIgnoreCase(ACCEPTED_VERSIONS, entry.request().httpVersion())
                || (!sendRequests
                        && !containsIgnoreCase(
                                ACCEPTED_VERSIONS, entry.response().httpVersion()))) {
            LOGGER.warn(
                    "Message with unsupported HTTP version (Req version: {}, Resp version: {}) will be dropped: {}",
                    entry.request().httpVersion(),
                    entry.response().httpVersion(),
                    entry.request().url());
            return false;
        }
        return true;
    }

    private static boolean entryIsNotLocalPrivate(HarEntry entry) {
        String url = entry.request().url();
        if (Strings.CI.startsWith(url, "about")
                || Strings.CI.startsWith(url, "chrome")
                || Strings.CI.startsWith(url, "edge")) {
            LOGGER.debug("Skipping local private entry: {}", url);
            return false;
        }
        return true;
    }

    protected static List<HttpMessage> getHttpMessages(HarLog log) {
        List<HttpMessage> result = new ArrayList<>();
        for (HarEntry entry : preProcessHarEntries(log, false)) {
            result.add(getHttpMessage(entry));
        }
        return result;
    }

    private static HttpMessage getHttpMessage(HarEntry harEntry) {
        try {
            return HarUtils.createHttpMessage(harEntry);
        } catch (HttpMalformedHeaderException headerEx) {
            LOGGER.warn(
                    "Failed to create HTTP Request/Response Header for HAR entry.\n{}",
                    headerEx.getMessage());
            return null;
        }
    }

    private static boolean containsIgnoreCase(List<String> checkList, String candidate) {
        return checkList.stream().anyMatch(e -> e.equalsIgnoreCase(candidate));
    }

    private static HarEntry correctHttpVersions(HarEntry entry) {
        HarEntryBuilder builder = entry.toBuilder();
        // Handle missing httpVersion (set http/1.1)
        boolean changed =
                preProcessHttpVersion(
                        entry,
                        builder,
                        CHECK_MISSING.test(entry.request().httpVersion()),
                        HttpHeader.HTTP11,
                        false);
        changed |=
                preProcessHttpVersion(
                        entry,
                        builder,
                        CHECK_MISSING.test(entry.response().httpVersion()),
                        HttpHeader.HTTP11,
                        true);
        // Handle http/3 (set http/2)
        changed |=
                preProcessHttpVersion(
                        entry,
                        builder,
                        CHECK_H3.test(entry.request().httpVersion()),
                        HttpHeader.HTTP2,
                        false);
        changed |=
                preProcessHttpVersion(
                        entry,
                        builder,
                        CHECK_H3.test(entry.response().httpVersion()),
                        HttpHeader.HTTP2,
                        true);

        return changed ? builder.build() : entry;
    }

    private static boolean preProcessHttpVersion(
            HarEntry entry,
            HarEntryBuilder builder,
            boolean condition,
            String vers,
            boolean response) {
        if (condition) {
            if (response) {
                builder.response(entry.response().toBuilder().httpVersion(vers).build());
            } else {
                builder.request(entry.request().toBuilder().httpVersion(vers).build());
            }
            LOGGER.info(
                    "Setting {} version to {} for {}",
                    response ? "response" : "request",
                    vers,
                    entry.request().url());
            return true;
        }
        return false;
    }

    private void persistMessage(HttpMessage message) {
        HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
            dataSource.messageSuccessful();
        } catch (Exception e) {
            LOGGER.warn(e.getMessage());
            dataSource.messageError();
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

    private interface HarProvider {
        Har from(HarReader data) throws HarReaderException;
    }
}
