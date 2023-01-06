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
package org.zaproxy.addon.exim;

import edu.umass.cs.benchlab.har.HarEntries;
import edu.umass.cs.benchlab.har.HarLog;
import java.awt.EventQueue;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.exim.har.HarImporter;
import org.zaproxy.addon.exim.log.LogsImporter;
import org.zaproxy.addon.exim.urls.UrlsImporter;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.HarUtils;

/** The API for importing data from a file. */
public class ImportExportApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(ImportExportApi.class);
    private static final String PREFIX = "exim";

    private static final String PARAM_BASE_URL = "baseurl";
    private static final String PARAM_COUNT = "count";
    private static final String PARAM_FILE_PATH = "filePath";
    private static final String PARAM_FOLLOW_REDIRECTS = "followRedirects";
    private static final String PARAM_IDS = "ids";
    private static final String PARAM_REQUEST = "request";
    private static final String PARAM_START = "start";

    private static final String ACTION_IMPORT_HAR = "importHar";
    private static final String ACTION_IMPORT_URLS = "importUrls";
    private static final String ACTION_IMPORT_ZAP_LOGS = "importZapLogs";
    private static final String ACTION_IMPORT_MODSEC2_LOGS = "importModsec2Logs";

    private static final String OTHER_EXPORT_HAR = "exportHar";
    private static final String OTHER_EXPORT_HAR_BY_ID = "exportHarById";
    private static final String OTHER_SEND_HAR_REQUEST = "sendHarRequest";

    private static ExtensionHistory extHistory;

    public ImportExportApi() {
        super();
        this.addApiAction(new ApiAction(ACTION_IMPORT_HAR, new String[] {PARAM_FILE_PATH}));
        this.addApiAction(new ApiAction(ACTION_IMPORT_URLS, new String[] {PARAM_FILE_PATH}));
        this.addApiAction(new ApiAction(ACTION_IMPORT_ZAP_LOGS, new String[] {PARAM_FILE_PATH}));
        this.addApiAction(
                new ApiAction(ACTION_IMPORT_MODSEC2_LOGS, new String[] {PARAM_FILE_PATH}));

        this.addApiOthers(
                new ApiOther(
                        OTHER_EXPORT_HAR,
                        null,
                        new String[] {PARAM_BASE_URL, PARAM_START, PARAM_COUNT}));
        this.addApiOthers(new ApiOther(OTHER_EXPORT_HAR_BY_ID, new String[] {PARAM_IDS}));

        this.addApiOthers(
                new ApiOther(
                        OTHER_SEND_HAR_REQUEST,
                        new String[] {PARAM_REQUEST},
                        new String[] {PARAM_FOLLOW_REDIRECTS}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiAction {} {}", name, params);

        File file;
        switch (name) {
            case ACTION_IMPORT_HAR:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                HarImporter harImporter = new HarImporter(file);
                return handleFileImportResponse(harImporter.isSuccess(), file);
            case ACTION_IMPORT_URLS:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                UrlsImporter importer = new UrlsImporter(file);
                return handleFileImportResponse(importer.isSuccess(), file);
            case ACTION_IMPORT_ZAP_LOGS:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                LogsImporter zapImporter = new LogsImporter(file, LogsImporter.LogType.ZAP);
                return handleFileImportResponse(zapImporter.isSuccess(), file);
            case ACTION_IMPORT_MODSEC2_LOGS:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                LogsImporter logsImporter =
                        new LogsImporter(file, LogsImporter.LogType.MOD_SECURITY_2);
                return handleFileImportResponse(logsImporter.isSuccess(), file);
            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params)
            throws ApiException {
        if (OTHER_EXPORT_HAR_BY_ID.equals(name) || OTHER_EXPORT_HAR.equals(name)) {
            byte[] responseBody;
            try {
                final HarEntries entries = new HarEntries();
                if (OTHER_EXPORT_HAR_BY_ID.equals(name)) {
                    TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
                    for (Integer id : getIds(params)) {
                        RecordHistory recordHistory = getRecordHistory(tableHistory, id);
                        addHarEntry(entries, recordHistory);
                    }
                } else {
                    processHttpMessages(
                            this.getParam(params, PARAM_BASE_URL, (String) null),
                            this.getParam(params, PARAM_START, -1),
                            this.getParam(params, PARAM_COUNT, -1),
                            rh -> addHarEntry(entries, rh));
                }

                HarLog harLog = HarUtils.createZapHarLog();
                harLog.setEntries(entries);

                responseBody = HarUtils.harLogToByteArray(harLog);
            } catch (ApiException e) {
                responseBody =
                        e.toString(API.Format.JSON, incErrorDetails())
                                .getBytes(StandardCharsets.UTF_8);
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);

                ApiException apiException =
                        new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
                responseBody =
                        apiException
                                .toString(API.Format.JSON, incErrorDetails())
                                .getBytes(StandardCharsets.UTF_8);
            }

            try {
                msg.setResponseHeader(
                        API.getDefaultResponseHeader(
                                "application/json; charset=UTF-8", responseBody.length));
            } catch (HttpMalformedHeaderException e) {
                LOGGER.error("Failed to create response header: {}", e.getMessage(), e);
            }
            msg.setResponseBody(responseBody);

            return msg;
        } else if (OTHER_SEND_HAR_REQUEST.equals(name)) {
            byte[] responseBody = {};
            HttpMessage request = null;
            try {
                request = HarUtils.createHttpMessage(params.getString(PARAM_REQUEST));
            } catch (IOException e) {
                ApiException apiException =
                        new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_REQUEST, e);
                responseBody =
                        apiException
                                .toString(API.Format.JSON, incErrorDetails())
                                .getBytes(StandardCharsets.UTF_8);
            }

            if (request != null) {
                if (!isValidForCurrentMode(request.getRequestHeader().getURI())) {
                    ApiException apiException = new ApiException(ApiException.Type.MODE_VIOLATION);
                    responseBody =
                            apiException
                                    .toString(API.Format.JSON, incErrorDetails())
                                    .getBytes(StandardCharsets.UTF_8);
                } else {
                    boolean followRedirects = getParam(params, PARAM_FOLLOW_REDIRECTS, false);
                    try {
                        final HarEntries entries = new HarEntries();
                        sendRequest(
                                request,
                                followRedirects,
                                httpMessage -> {
                                    HistoryReference hRef = httpMessage.getHistoryRef();
                                    entries.addEntry(
                                            HarUtils.createHarEntry(
                                                    hRef.getHistoryId(),
                                                    hRef.getHistoryType(),
                                                    httpMessage));
                                });

                        HarLog harLog = HarUtils.createZapHarLog();
                        harLog.setEntries(entries);

                        responseBody = HarUtils.harLogToByteArray(harLog);
                    } catch (ApiException e) {
                        responseBody =
                                e.toString(API.Format.JSON, incErrorDetails())
                                        .getBytes(StandardCharsets.UTF_8);
                    } catch (Exception e) {
                        LOGGER.error(e.getMessage(), e);

                        ApiException apiException =
                                new ApiException(ApiException.Type.INTERNAL_ERROR, e.getMessage());
                        responseBody =
                                apiException
                                        .toString(API.Format.JSON, incErrorDetails())
                                        .getBytes(StandardCharsets.UTF_8);
                    }
                }
            }

            try {
                msg.setResponseHeader(
                        API.getDefaultResponseHeader(
                                "application/json; charset=UTF-8", responseBody.length));
            } catch (HttpMalformedHeaderException e) {
                LOGGER.error("Failed to create response header: {}", e.getMessage(), e);
            }
            msg.setResponseBody(responseBody);

            return msg;
        } else {
            throw new ApiException(ApiException.Type.BAD_OTHER);
        }
    }

    private ApiResponseElement handleFileImportResponse(boolean success, File file)
            throws ApiException {
        if (success) {
            return ApiResponseElement.OK;
        }
        throw new ApiException(Type.BAD_EXTERNAL_DATA, file.getAbsolutePath());
    }

    private RecordHistory getRecordHistory(TableHistory tableHistory, Integer id)
            throws ApiException {
        RecordHistory recordHistory;
        try {
            recordHistory = tableHistory.read(id);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.error("Failed to read the history record:", e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR, e);
        }
        if (recordHistory == null) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, Integer.toString(id));
        }
        return recordHistory;
    }

    private static List<Integer> getIds(JSONObject params) throws ApiException {
        List<Integer> listIds = new ArrayList<>();
        for (String id : params.getString(PARAM_IDS).split(",")) {
            try {
                listIds.add(Integer.valueOf(id.trim()));
            } catch (NumberFormatException e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_IDS, e);
            }
        }

        if (listIds.isEmpty()) {
            throw new ApiException(ApiException.Type.MISSING_PARAMETER, PARAM_IDS);
        }
        return listIds;
    }

    /**
     * Adds the given history record to the given {@code entries}.
     *
     * @param entries where to add the new {@code HarEntry}.
     * @param recordHistory the history record to add, after converting to {@code HarEntry}.
     * @see HarUtils#createHarEntry(int, int, HttpMessage)
     */
    private static void addHarEntry(HarEntries entries, RecordHistory recordHistory) {
        entries.addEntry(
                HarUtils.createHarEntry(
                        recordHistory.getHistoryId(),
                        recordHistory.getHistoryType(),
                        recordHistory.getHttpMessage()));
    }

    private boolean incErrorDetails() {
        return Model.getSingleton().getOptionsParam().getApiParam().isIncErrorDetails();
    }

    private void processHttpMessages(
            String baseUrl, int start, int count, Processor<RecordHistory> processor)
            throws ApiException {
        try {
            TableHistory tableHistory = Model.getSingleton().getDb().getTableHistory();
            List<Integer> historyIds =
                    tableHistory.getHistoryIds(Model.getSingleton().getSession().getSessionId());

            PaginationConstraintsChecker pcc = new PaginationConstraintsChecker(start, count);
            for (Integer id : historyIds) {
                RecordHistory recHistory = tableHistory.read(id);

                HttpMessage msg = recHistory.getHttpMessage();

                if (msg.getRequestHeader().isImage() || msg.getResponseHeader().isImage()) {
                    continue;
                }

                if (baseUrl != null
                        && !msg.getRequestHeader().getURI().toString().startsWith(baseUrl)) {
                    // Not subordinate to the specified URL
                    continue;
                }

                pcc.recordProcessed();
                if (!pcc.hasPageStarted()) {
                    continue;
                }

                processor.process(recHistory);
                if (pcc.hasPageEnded()) {
                    break;
                }
            }
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
            throw new ApiException(ApiException.Type.INTERNAL_ERROR);
        }
    }

    private static void sendRequest(
            HttpMessage request, boolean followRedirects, Processor<HttpMessage> processor)
            throws IOException, ApiException {
        HttpSender sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

        if (followRedirects) {
            ModeRedirectionValidator redirector = new ModeRedirectionValidator(processor);
            sender.sendAndReceive(
                    request,
                    HttpRequestConfig.builder().setRedirectionValidator(redirector).build());

            if (!redirector.isRequestValid()) {
                throw new ApiException(ApiException.Type.MODE_VIOLATION);
            }
        } else {
            sender.sendAndReceive(request, false);
            persistMessage(request);
            processor.process(request);
        }
    }

    private static void persistMessage(final HttpMessage message) {
        final HistoryReference historyRef;

        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_ZAP_USER,
                            message);
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
            return;
        }

        if (getExtHistory() != null) {
            EventQueue.invokeLater(
                    () -> {
                        getExtHistory().addHistory(historyRef);
                        Model.getSingleton()
                                .getSession()
                                .getSiteTree()
                                .addPath(historyRef, message);
                    });
        }
    }

    /**
     * Tells whether or not the given {@code uri} is valid for the current {@link Mode}.
     *
     * <p>The {@code uri} is not valid if the mode is {@code safe} or if in {@code protect} mode is
     * not in scope.
     *
     * @param uri the {@code URI} that will be validated
     * @return {@code true} if the given {@code uri} is valid, {@code false} otherwise.
     */
    private static boolean isValidForCurrentMode(URI uri) {
        switch (Control.getSingleton().getMode()) {
            case safe:
                return false;
            case protect:
                return Model.getSingleton().getSession().isInScope(uri.toString());
            default:
                return true;
        }
    }

    private static ExtensionHistory getExtHistory() {
        if (extHistory == null) {
            extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return extHistory;
    }

    private interface Processor<T> {

        void process(T object);
    }

    private static class PaginationConstraintsChecker {

        private boolean pageStarted;
        private boolean pageEnded;
        private final int startRecord;
        private final boolean hasEnd;
        private final int finalRecord;
        private int recordsProcessed;

        public PaginationConstraintsChecker(int start, int count) {
            recordsProcessed = 0;

            if (start > 0) {
                pageStarted = false;
                startRecord = start;
            } else {
                pageStarted = true;
                startRecord = 0;
            }

            if (count > 0) {
                hasEnd = true;
                finalRecord = !pageStarted ? start + count - 1 : count;
            } else {
                hasEnd = false;
                finalRecord = 0;
            }
            pageEnded = false;
        }

        public void recordProcessed() {
            ++recordsProcessed;

            if (!pageStarted) {
                pageStarted = recordsProcessed >= startRecord;
            }

            if (hasEnd && !pageEnded) {
                pageEnded = recordsProcessed >= finalRecord;
            }
        }

        public boolean hasPageStarted() {
            return pageStarted;
        }

        public boolean hasPageEnded() {
            return pageEnded;
        }
    }

    /**
     * A {@link HttpRedirectionValidator} that enforces the {@link Mode} when validating the {@code
     * URI} of redirections.
     *
     * @see #isRequestValid()
     */
    private static class ModeRedirectionValidator implements HttpRedirectionValidator {

        private final Processor<HttpMessage> processor;
        private boolean isRequestValid;

        public ModeRedirectionValidator(Processor<HttpMessage> processor) {
            this.processor = processor;
            this.isRequestValid = true;
        }

        @Override
        public void notifyMessageReceived(HttpMessage message) {
            persistMessage(message);
            processor.process(message);
        }

        @Override
        public boolean isValid(URI redirection) {
            isRequestValid = isValidForCurrentMode(redirection);
            return isRequestValid;
        }

        /**
         * Tells whether or not the request is valid, that is, all redirections were valid for the
         * current {@link Mode}.
         *
         * @return {@code true} is the request is valid, {@code false} otherwise.
         */
        public boolean isRequestValid() {
            return isRequestValid;
        }
    }
}
