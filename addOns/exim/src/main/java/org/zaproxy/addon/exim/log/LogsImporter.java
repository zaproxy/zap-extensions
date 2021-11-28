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
import java.util.Collections;
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
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.utils.Stats;

public final class LogsImporter {

    private static final Logger LOG = LogManager.getLogger(LogsImporter.class);
    private static final String STATS_ZAP_FILE = "import.zap.file";
    private static final String STATS_ZAP_FILE_ERROR = "import.zap.file.errors";
    private static final String STATS_ZAP_FILE_MSG = "import.zap.file.message";
    private static final String STATS_ZAP_FILE_MSG_ERROR = "import.zap.file.message.errors";
    private static final String STATS_MODSEC2_FILE = "import.modsec2.file";
    private static final String STATS_MODSEC2_FILE_ERROR = "import.modsec2.file.errors";
    private static final String STATS_MODSEC2_FILE_MSG = "import.modsec2.file.message";
    private static final String STATS_MODSEC2_FILE_MSG_ERROR = "import.modsec2.file.message.errors";

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

    private LogsImporter() {
        // Utility class
    }

    private static void readModSecLogsFromFile(File file) {
        try {
            processModSecLogs(new ModSecurity2AuditReader(file));
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private static void processModSecLogs(ModSecurity2AuditReader reader) throws IOException {

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
                }
                break;
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
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
    public static boolean processInput(File newFile, LogType logChoice) {
        if (logChoice == LogType.ZAP) {
            List<String> parsedText = readFile(newFile);
            try {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE);
                updateOutput("exim.output.start", newFile.toPath().toString());
                processZapLogs(parsedText);
                updateOutput("exim.output.end", newFile.toPath().toString());
            } catch (HttpMalformedHeaderException e) {
                LOG.error(e.getMessage(), e);
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE_ERROR);
                updateOutput("exim.output.error", newFile.toPath().toString());
                return false;
            }
        } else if (logChoice == LogType.MOD_SECURITY_2) {
            try {
                updateOutput("exim.output.start", newFile.toPath().toString());
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE);
                readModSecLogsFromFile(newFile);
                updateOutput("exim.output.end", newFile.toPath().toString());
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE_ERROR);
                updateOutput("exim.output.error", newFile.toPath().toString());
                return false;
            }
        }
        return true;
    }

    private static List<String> readFile(File file) {
        List<String> parsed = new ArrayList<>();
        Charset charset = StandardCharsets.US_ASCII;
        try (BufferedReader reader = Files.newBufferedReader(file.toPath(), charset)) {
            Scanner sc = new Scanner(reader);
            sc.useDelimiter(Pattern.compile("====\\s[0-9]*\\s=========="));
            while (sc.hasNext()) {
                parsed.add(sc.next());
            }
            sc.close();
            return parsed;
        } catch (IOException e) {
            LOG.error(e.getMessage(), e);
        }
        return Collections.emptyList();
    }

    private static void processZapLogs(List<String> parsedRequestAndResponse)
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
            LOG.error(e.getMessage(), e);
            if (LogType.ZAP.equals(logType)) {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_ZAP_FILE_MSG_ERROR);
            } else {
                Stats.incCounter(ExtensionExim.STATS_PREFIX + STATS_MODSEC2_FILE_MSG_ERROR);
            }
        }
    }

    private static void updateOutput(String messageKey, String filePath) {
        if (View.isInitialised()) {
            StringBuilder sb = new StringBuilder(128);
            sb.append(Constant.messages.getString(messageKey, filePath)).append('\n');
            View.getSingleton().getOutputPanel().append(sb.toString());
        }
    }
}
