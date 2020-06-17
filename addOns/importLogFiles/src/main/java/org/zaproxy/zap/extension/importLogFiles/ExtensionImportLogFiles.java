/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.importLogFiles;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.log4j.Logger;
import org.jwall.web.audit.AuditEvent;
import org.jwall.web.audit.io.ModSecurity2AuditReader;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionImportLogFiles extends ExtensionAdaptor {

    /** Logging options for the import */
    public static enum LogType {
        ZAP("zap"),
        MOD_SECURITY_2("modsec2");

        private String i18nKey;

        private LogType(String i18nKey) {
            this.i18nKey = i18nKey;
        }

        @Override
        public String toString() {
            return Constant.messages.getString("importLogFiles.log.type." + i18nKey);
        }
    }

    private ZapMenuItem menuExample = null;

    private static Logger log = Logger.getLogger(ExtensionImportLogFiles.class);

    private ImportLogAPI importLogAPI;

    public ExtensionImportLogFiles() {
        super("ExtensionImportLogFiles");
    }

    @SuppressWarnings("deprecation")
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        importLogAPI = new ImportLogAPI(null);
        extensionHook.addApiImplementor(importLogAPI);
        if (getView() != null) {
            extensionHook.getHookMenu().addImportMenuItem(getImportOption());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private ZapMenuItem getImportOption() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem("importLogFiles.import.importLOG");

            menuExample.addActionListener(
                    new java.awt.event.ActionListener() {

                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {

                            View view = View.getSingleton();
                            JFrame main = view.getMainFrame();
                            JFileChooser fc = new JFileChooser();
                            fc.setAcceptAllFileFilterUsed(false);
                            FileFilter filter =
                                    new FileNameExtensionFilter(
                                            getMessageString(
                                                    "importLogFiles.choosefile.filter.description"),
                                            "txt");
                            fc.addChoosableFileFilter(filter);

                            LogType logChoice =
                                    (LogType)
                                            JOptionPane.showInputDialog(
                                                    main,
                                                    getMessageString(
                                                            "importLogFiles.choosefile.message"),
                                                    getMessageString(
                                                            "importLogFiles.choosefile.title"),
                                                    JOptionPane.QUESTION_MESSAGE,
                                                    null,
                                                    LogType.values(),
                                                    LogType.ZAP);

                            if (logChoice != null) {
                                int openChoice = fc.showOpenDialog(main);
                                if (openChoice == JFileChooser.APPROVE_OPTION) {
                                    File newFile = fc.getSelectedFile();
                                    processInput(newFile, logChoice);
                                }
                            }
                        }
                    });
        }
        return menuExample;
    }

    public List<HttpMessage> ReadModSecAuditEvent(InputStream stream) {
        ModSecurity2AuditReader reader = null;
        try {
            reader = new ModSecurity2AuditReader(stream);
            return readModSecLogs(reader);
        } catch (Exception e) {

            log.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * For reading logs that are exported from the ModSecurity application
     *
     * @param newFile java.io.File object referring to the ModSecurity text log file
     * @return List of HttpMessages containing Request Header and Body and Response Header and Body
     * @throws IOException
     */
    public List<HttpMessage> readModSecLogsFromFile(File newFile) {
        ModSecurity2AuditReader reader = null;
        try {
            reader = new ModSecurity2AuditReader(newFile);
            return readModSecLogs(reader);
        } catch (Exception e) {

            log.error(e.getMessage(), e);
        }
        return null;
    }

    private synchronized List<HttpMessage> readModSecLogs(ModSecurity2AuditReader reader)
            throws IOException {
        List<HttpMessage> messages = new ArrayList<>();

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
                    messages.add(httpMessage);
                } else break;
            } catch (Exception e) {
                // View.getSingleton().showWarningDialog("Cannot import this log as it does not
                // match the ModSecurity2 data format");
                log.error(e.getMessage(), e);
            }
        }

        reader.close();

        if (messages.size() == 0) {
            return null;
        }
        return messages;
    }

    /**
     * Updates the UI view with the newly added HttpMessages This method needs to be public as it
     * can be called internally and by the API
     *
     * @param historyList List of History References returned from adding HttpMessages to the ZAP
     *     database
     */
    public void addToTree(List<HistoryReference> historyList) {
        SiteMap currentTree = Model.getSingleton().getSession().getSiteTree();

        for (HistoryReference historyref : historyList) {
            currentTree.addPath(historyref);
        }

        currentTree.reload();
        // /Need to refresh history tabs for details and alerts refresh
    }

    /**
     * Switch method called by the entry point for the log imports to choose path to take based on
     * the log type selected by the user
     *
     * @param newFile java.IO.File representation of the logfile, called from both the UI and from
     *     the API
     * @param logChoice type of logfile being imported
     */
    public void processInput(File newFile, LogType logChoice) {
        if (logChoice == LogType.ZAP) {
            List<String> parsedText = readFile(newFile);
            try {
                List<HttpMessage> messages = getHttpMessages(parsedText);
                List<HistoryReference> history = getHistoryRefs(messages);
                addToTree(history);
            } catch (HttpMalformedHeaderException e) {
                log.error(e.getMessage(), e);
            }
        } else if (logChoice == LogType.MOD_SECURITY_2) {
            try {
                List<HttpMessage> messages = readModSecLogsFromFile(newFile);
                List<HistoryReference> history = getHistoryRefs(messages);
                SiteMap currentTree = Model.getSingleton().getSession().getSiteTree();
                for (HistoryReference historyref : history) {
                    currentTree.addPath(historyref);
                }
                currentTree.reload();
                // /Need to refresh history tabs for details.
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        }
    }

    List<String> readFile(File file) {
        return readFileFromPath(Paths.get(file.getPath()));
    }

    List<String> readFileFromPath(Path filePath) {
        List<String> parsed = new ArrayList<String>();
        Charset charset = Charset.forName("US-ASCII");
        try (BufferedReader reader = Files.newBufferedReader(filePath, charset)) {
            Scanner sc = new Scanner(reader);
            sc.useDelimiter(Pattern.compile("====\\s[0-9]*\\s=========="));
            while (sc.hasNext()) {
                parsed.add(sc.next());
            }
            sc.close();
            return parsed;
        } catch (IOException x) {
            log.error(x.getMessage(), x);
        }
        return null;
    }

    /**
     * Called exclusively by the REST API to get the HttpMessage ZAP object representation of the
     * request response pair.
     *
     * @param request HttpRequest string
     * @param response HttpRespones string
     * @return List of the HttpMessage objects
     * @throws HttpMalformedHeaderException
     */
    public List<HttpMessage> getHttpMessageFromPair(String request, String response)
            throws HttpMalformedHeaderException {
        List<String> reqResp = new ArrayList<>(2);
        reqResp.add(request);
        reqResp.add(response);
        return getHttpMessages(reqResp);
    }

    private List<HttpMessage> getHttpMessages(List<String> parsedrequestandresponse)
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

        // Initialise list at total parsed message count for performance.
        List<HttpMessage> messages = new ArrayList<>(parsedrequestandresponse.size());

        for (String block : parsedrequestandresponse) {
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
                // i.e. on a Post request there's
                // a token in the body usually
                // So I'm using the group matching in the regex to split that up. We'll need either
                // a blank HttpRequestBody or
                // the actual one further down the line.
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
                messages.add(httpMessage);
            }
        }
        return messages;
    }

    public List<HistoryReference> getHistoryRefs(List<HttpMessage> messages)
            throws HttpMalformedHeaderException {
        // Initialise list at total parsed message count for performance.
        List<HistoryReference> historyRefs = new ArrayList<>(messages.size());
        Session currentSession = Model.getSingleton().getSession();

        for (HttpMessage message : messages) {
            try {
                historyRefs.add(new HistoryReference(currentSession, 1, message));
            } catch (DatabaseException e) {
                log.error(e.getMessage(), e);
            } catch (HttpMalformedHeaderException e) {
                log.error(e.getMessage(), e);
            } catch (NullPointerException n) {
                log.error(n.getMessage(), n);
            }
        }
        return historyRefs;
    }

    public String getMessageString(String key) {
        return getMessages().getString(key);
    }

    @Override
    public String getDescription() {
        return getMessages().getString("importLogFiles.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(
                    "https://github.com/zaproxy/zaproxy/wiki/MozillaMentorship_ImportingModSecurityLogs");
        } catch (MalformedURLException e) {
            return null;
        }
    }
}
