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
package org.zaproxy.addon.exim.log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jwall.web.audit.AuditEvent;
import org.jwall.web.audit.io.ModSecurity2AuditReader;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.ui.ProgressPaneListener;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.utils.Stats;

public class LogsImporter {

    private static final Logger LOG = LogManager.getLogger(LogsImporter.class);
    private static final String STATS_ZAP_FILE = "import.zap.file";
    private static final String STATS_ZAP_FILE_ERROR = "import.zap.file.errors";
    private static final String STATS_ZAP_FILE_MSG = "import.zap.file.message";
    private static final String STATS_ZAP_FILE_MSG_ERROR = "import.zap.file.message.errors";
    private static final String STATS_MODSEC2_FILE = "import.modsec2.file";
    private static final String STATS_MODSEC2_FILE_ERROR = "import.modsec2.file.errors";
    private static final String STATS_MODSEC2_FILE_MSG = "import.modsec2.file.message";
    private static final String STATS_MODSEC2_FILE_MSG_ERROR = "import.modsec2.file.message.errors";

    private ProgressPaneListener progressListener;
    private boolean success;

    /** Logging options for the import */
    public enum LogType {
        ZAP("zap"),
        MOD_SECURITY_2("modsec2");

        private String i18nKey;

        private LogType(String i18nKey) {
            this.i18nKey = i18nKey;
        }

        @Override
        public String toString() {
            return Constant.messages.getString("exim.importLogFiles.log.type." + i18nKey);
        }
    }

    public LogsImporter(File file, LogType type) {
        this(file, type, null);
    }

    public LogsImporter(File file, LogType type, ProgressPaneListener listener) {
        this.progressListener = listener;
        success = processInput(file, type);
        completed();
    }

    private void readModSecLogsFromFile(File file) throws Exception {
        processModSecLogs(new ModSecurity2AuditReader(file));
    }

    private void processModSecLogs(ModSecurity2AuditReader reader) throws IOException {

        while (reader.bytesRead() < reader.bytesAvailable()) {
            try {
                AuditEvent a = reader.readNext();
                if (a != null) {
                    // Mod Security logs don't provide http response bodies to load in.
                    HttpMessage httpMessage =
                            new HttpMessage(
                                    new HttpRequestHeader(a.getRequestHeader()),
                                    new HttpRequestBody(a.getRequestBody()),
                                    new HttpResponseHeader(a.getResponseHeader()),
                                    new HttpResponseBody());
                    httpMessage.setResponseFromTargetHost(true);
                    createHistoryReferenceAndAddToTree(httpMessage, LogType.MOD_SECURITY_2);
                    updateProgress(httpMessage.getRequestHeader().getURI().toString());
                }
                break;
            } catch (Exception e) {
                LOG.warn(e.getMessage());
            }
        }

        reader.close();
    }

    private static void addToTree(HistoryReference historyRef) {
        SiteMap currentTree = Model.getSingleton().getSession().getSiteTree();
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

        currentTree.addPath(historyRef);
        extHistory.addHistory(historyRef);
    }

    /**
     * Switch method called by the entry point for the log imports to choose path to take based on
     * the log type selected by the user
     *
     * @param newFile java.IO.File representation of the logfile, called from both the UI and from
     *     the API
     * @param logChoice type of logfile being imported
     */
    private boolean processInput(File newFile, LogType logChoice) {
        if (logChoice == LogType.ZAP) {
            try {
                List<String> parsedText = readFile(newFile);
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE);
                ExtensionExim.updateOutput("exim.output.start", newFile.toPath().toString());
                processZapLogs(parsedText);
                ExtensionExim.updateOutput("exim.output.end", newFile.toPath().toString());
            } catch (IOException e) {
                LOG.warn(e.getMessage());
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE_ERROR);
                ExtensionExim.updateOutput(
                        ExtensionExim.EXIM_OUTPUT_ERROR, newFile.getAbsolutePath());
                return false;
            }
        } else if (logChoice == LogType.MOD_SECURITY_2) {
            try {
                ExtensionExim.updateOutput("exim.output.start", newFile.toPath().toString());
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE);
                readModSecLogsFromFile(newFile);
                ExtensionExim.updateOutput("exim.output.end", newFile.toPath().toString());
            } catch (Exception e) {
                LOG.warn(e.getMessage());
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE_ERROR);
                ExtensionExim.updateOutput(
                        ExtensionExim.EXIM_OUTPUT_ERROR, newFile.getAbsolutePath());
                return false;
            }
        }
        return true;
    }

    private static List<String> readFile(File file) throws IOException {
        List<String> parsed = new ArrayList<>();
        Charset charset = StandardCharsets.US_ASCII;
        BufferedReader reader = Files.newBufferedReader(file.toPath(), charset);
        Scanner sc = new Scanner(reader);
        sc.useDelimiter(Pattern.compile("====\\s[0-9]*\\s=========="));
        while (sc.hasNext()) {
            parsed.add(sc.next());
        }
        sc.close();
        return parsed;
    }

    private void processZapLogs(List<String> parsedRequestAndResponse)
            throws HttpMalformedHeaderException {
        // http://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
        Pattern requestP =
                Pattern.compile("^OPTIONS|^GET|^HEAD|^POST|^PUT|^DELETE|^TRACE|^CONNECT");

        // http://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html
        // Not sure whether to use the allchars-then-allwhitespacechars or just the DOTALL to get
        // the httprequestbody?
        Pattern responseP =
                Pattern.compile(
                        "(\\S*\\s*)?(HTTP/[0-9].[0-9]\\s[0-9]{3}.*)",
                        Pattern.DOTALL | Pattern.MULTILINE);
        // Pattern responseP = Pattern.compile("(.*)?(HTTP/[0-9].[0-9]\\s[0-9]{3}.*)",
        // Pattern.DOTALL | Pattern.MULTILINE);

        // Add capture group as we want to just match the html, not the rest of the payload
        Pattern responseBodyP =
                Pattern.compile("\\S*?(<html>.*</html>)", Pattern.DOTALL | Pattern.MULTILINE);

        HttpRequestHeader tempRequestHeader = null;
        HttpRequestBody tempRequestBody = new HttpRequestBody();
        HttpResponseHeader tempResponseHeader = null;
        HttpResponseBody tempResponseBody = new HttpResponseBody();

        for (String block : parsedRequestAndResponse) {
            // HTTP request and response header pairs have a 2 line break between them as per RFC
            // 2616
            // http://tools.ietf.org/html/rfc2616
            String[] httpComponents = block.split("\r\n\r\n");
            for (String component : httpComponents) {
                // Remove leading and trailing whitespace
                component = component.trim();

                Matcher requestM = requestP.matcher(component);
                if (requestM.find()) {
                    tempRequestHeader = new HttpRequestHeader(component);
                }

                // Strange way of splitting it up but usually if the httpRequestBody is present,
                // i.e. on a Post request there's a token in the body usually
                // So I'm using the group matching in the regex to split that up. We'll need either
                // a blank HttpRequestBody or the actual one further down the line.
                Matcher responseM = responseP.matcher(component);
                if (responseM.find()) {
                    if (!responseM.group(1).trim().isEmpty())
                        tempRequestBody = new HttpRequestBody(responseM.group(1).trim());

                    tempResponseHeader = new HttpResponseHeader(responseM.group(2).trim());
                }
                Matcher responseBodyM = responseBodyP.matcher(component);
                if (responseBodyM.find()) {
                    tempResponseBody = new HttpResponseBody(responseBodyM.group(1));
                }
            }

            if (tempRequestHeader != null && tempResponseHeader != null) {
                HttpMessage httpMessage =
                        new HttpMessage(
                                tempRequestHeader,
                                tempRequestBody,
                                tempResponseHeader,
                                tempResponseBody);
                httpMessage.setResponseFromTargetHost(true);
                createHistoryReferenceAndAddToTree(httpMessage, LogType.ZAP);
                updateProgress(httpMessage.getRequestHeader().getURI().toString());
            }
        }
    }

    private static void createHistoryReferenceAndAddToTree(HttpMessage message, LogType logType) {
        Session currentSession = Model.getSingleton().getSession();

        try {
            HistoryReference historyRef =
                    new HistoryReference(currentSession, HistoryReference.TYPE_ZAP_USER, message);
            addToTree(historyRef);
            if (LogType.ZAP.equals(logType)) {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE_MSG);
            } else {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE_MSG);
            }
        } catch (DatabaseException | HttpMalformedHeaderException | NullPointerException e) {
            LOG.warn(e.getMessage());
            if (LogType.ZAP.equals(logType)) {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE_MSG_ERROR);
            } else {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE_MSG_ERROR);
            }
        }
    }

    public boolean isSuccess() {
        return success;
    }

    private void updateProgress(String line) {
        if (progressListener != null) {
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
