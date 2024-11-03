/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.pcap;

import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.zap.utils.ThreadUtils;

public class PcapImporter {

    private static final Logger LOGGER = LogManager.getLogger(PcapImporter.class);

    private static ExtensionHistory extHistory;

    private ProgressPaneListener progressListener;
    private boolean success;

    public PcapImporter(File file) {
        importPcapFile(file);
    }

    public PcapImporter(File file, ProgressPaneListener listener) {
        this.progressListener = listener;
        importPcapFile(file);
    }

    private void importPcapFile(File file) {
        List<HttpMessage> messages = null;

        try {
            messages = getHttpMessages(file);
        } catch (IOException e) {
            LOGGER.warn("Failed to read Pcap file: {}\n{}", file.getAbsolutePath(), e.getMessage());
            success = false;
            completed();
            return;
        }

        progressListener.setTotalTasks(messages.size());
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
        success = true;
        completed();
    }

    protected static List<HttpMessage> getHttpMessages(File pcapFile) throws IOException {
        return PcapUtils.extractHttpMessages(pcapFile);
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
            LOGGER.warn(e.getMessage());
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
