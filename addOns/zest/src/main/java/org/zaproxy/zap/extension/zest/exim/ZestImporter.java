/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.exim;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;
import org.zaproxy.zest.core.v1.ZestElement;
import org.zaproxy.zest.core.v1.ZestJSON;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;
import org.zaproxy.zest.core.v1.ZestYaml;

/** Imports HTTP messages from Zest script files into ZAP history without replaying them. */
public class ZestImporter {

    private static final Logger LOGGER = LogManager.getLogger(ZestImporter.class);
    private static final String STATS_ZEST_FILE = "import.zest.file";
    private static final String STATS_ZEST_FILE_MSG = "import.zest.file.message";
    private static final String STATS_ZEST_FILE_MSG_ERROR = "import.zest.file.message.errors";
    private static final String STATS_ZEST_FILE_ERROR = "import.zest.file.errors";

    private static ExtensionHistory extHistory;

    private ProgressPaneListener progressListener;
    private boolean success;
    private String lastError;

    public ZestImporter(File file) {
        this(file, null);
    }

    public ZestImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            ZestScript script = parseScript(content, file.getAbsolutePath());
            if (script != null) {
                importZestScript(script);
            } else {
                success = false;
                if (lastError == null) {
                    lastError = Constant.messages.getString("zest.exim.file.import.error.invalid");
                }
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE_ERROR);
            }
        } catch (IOException e) {
            lastError =
                    Constant.messages.getString("zest.exim.file.import.error.read", e.getMessage());
            LOGGER.warn("Failed to read Zest file: {}", file.getAbsolutePath(), e);
            success = false;
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE_ERROR);
        } finally {
            completed();
        }
    }

    private ZestScript parseScript(String content, String filePath) {
        if (content == null || content.isBlank()) {
            lastError = Constant.messages.getString("zest.exim.file.import.error.empty");
            return null;
        }
        try {
            ZestElement element =
                    content.trim().startsWith("{")
                            ? ZestJSON.fromString(content)
                            : ZestYaml.fromString(content);
            if (element instanceof ZestScript) {
                return (ZestScript) element;
            }
            lastError = Constant.messages.getString("zest.exim.file.import.error.not.script");
            return null;
        } catch (Exception e) {
            lastError =
                    Constant.messages.getString(
                            "zest.exim.file.import.error.parse", e.getMessage());
            LOGGER.warn("Failed to parse Zest script from {}: {}", filePath, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Returns the error message from the last import attempt, or {@code null} if the import
     * succeeded.
     *
     * @return the error message, or {@code null}
     */
    public String getLastError() {
        return lastError;
    }

    private void importZestScript(ZestScript script) {
        Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE);

        long requestCount =
                script.getStatements().stream().filter(ZestRequest.class::isInstance).count();
        if (progressListener != null) {
            progressListener.setTotalTasks((int) requestCount);
        }

        int count = 0;
        for (ZestStatement statement : script.getStatements()) {
            if (statement instanceof ZestRequest) {
                ZestRequest request = (ZestRequest) statement;
                try {
                    HttpMessage msg = ZestZapUtils.toHttpMessage(request, request.getResponse());
                    if (msg != null) {
                        msg.setResponseFromTargetHost(true);
                        persistMessage(msg);
                        count++;
                        updateProgress(count, msg.getRequestHeader().getURI().toString());
                    }
                } catch (Exception e) {
                    LOGGER.debug(
                            "Failed to convert Zest request to HTTP message: {}", e.getMessage());
                    Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE_MSG_ERROR);
                }
            }
        }
        success = true;
    }

    private static void persistMessage(HttpMessage message) {
        HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE_MSG);
        } catch (Exception e) {
            LOGGER.warn(e.getMessage());
            Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZEST_FILE_MSG_ERROR);
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
        if (getExtensionHistory() != null) {
            getExtensionHistory().addHistory(historyRef);
            Model.getSingleton().getSession().getSiteTree().addPath(historyRef, message);
        }
    }

    public boolean isSuccess() {
        return success;
    }

    private void updateProgress(int count, String line) {
        if (progressListener != null) {
            progressListener.setTasksDone(count);
            progressListener.setCurrentTask(
                    Constant.messages.getString("zest.exim.progress.currentimport", line));
        }
    }

    private void completed() {
        if (progressListener != null) {
            progressListener.completed();
        }
    }
}
