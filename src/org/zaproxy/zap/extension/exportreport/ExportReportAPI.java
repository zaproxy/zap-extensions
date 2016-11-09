/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * This file is based on the Paros code file ReportLastScan.java
 */
package org.zaproxy.zap.extension.exportreport;

import java.util.ArrayList;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.exportreport.filechooser.FileList;
import org.zaproxy.zap.extension.exportreport.filechooser.FileType;

import net.sf.json.JSONObject;

/**
 * The API for export report.
 *
 * AUTHOR: GORAN SARENKAPA - JordanGS
 * SPONSOR: RYERSON UNIVERSITY
 *
 */
public class ExportReportAPI extends ApiImplementor {

    private static final Logger logger = Logger.getLogger(ExportReportAPI.class);

    private static final String PREFIX = "exportreport";

    private static final String ACTION_GENERATE = "generate";
    private static final String VIEW_FORMATS = "formats";

    private static final String ACTION_PARAM_ABSOLUTE_PATH = "absolutePath";
    private static final String ACTION_PARAM_FILE_EXTENSION = "fileExtension";
    private static final String ACTION_PARAM_SOURCE_DETAILS = "sourceDetails";
    private static final String ACTION_PARAM_ALERT_SEVERITY = "alertSeverity";
    private static final String ACTION_PARAM_ALERT_DETAILS = "alertDetails";

    private ExtensionExportReport extension;

    public ExportReportAPI(ExtensionExportReport extension) {
        super();
        this.extension = extension;

        this.addApiAction(
                new ApiAction( ACTION_GENERATE,
                new String[] { ACTION_PARAM_ABSOLUTE_PATH,
                               ACTION_PARAM_FILE_EXTENSION,
                               ACTION_PARAM_SOURCE_DETAILS,
                               ACTION_PARAM_ALERT_SEVERITY,
                               ACTION_PARAM_ALERT_DETAILS }));
        this.addApiView(new ApiView(VIEW_FORMATS));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        if (logger.isDebugEnabled()) {
            logger.debug("Request for handleApiAction: " + name + " (params: " + params.toString() + ")");
        }

        switch (name) {
        case ACTION_GENERATE:
            String absolutePath = params.getString(ACTION_PARAM_ABSOLUTE_PATH);

            String fileExtension = params.getString(ACTION_PARAM_FILE_EXTENSION);

            if (!extension.canWrite(absolutePath)) {
                logger.warn(Constant.messages.getString("exportreport.message.console.error.file.writable", absolutePath));
                return ApiResponseElement.FAIL;
            }

            boolean valid = false;

            if (fileExtension.length() > 0) {
                valid = true;
            }
            if (!valid) {
                logger.warn(Constant.messages.getString("exportreport.message.console.error.file.extension", fileExtension));
                return ApiResponseElement.FAIL;
            }

            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.path"));
            }
            ArrayList<String> sourceDetails = new ArrayList<String>(Arrays.asList((params.getString(ACTION_PARAM_SOURCE_DETAILS)).split(";")));
            ArrayList<String> alertSeverityFlags = new ArrayList<String>(Arrays.asList((params.getString(ACTION_PARAM_ALERT_SEVERITY)).split(";")));
            ArrayList<String> alertDetailsFlags = new ArrayList<String>(Arrays.asList((params.getString(ACTION_PARAM_ALERT_DETAILS)).split(";")));

            if (sourceDetails.size() != extension.SOURCE_COUNT) {
                logger.error(Constant.messages.getString("exportreport.message.console.error.source", Constant.messages.getString("exportreport.menu.source.label"), sourceDetails.size(), extension.SOURCE_COUNT, Constant.messages.getString("exportreport.source.title.label"), Constant.messages.getString("exportreport.source.by.label"), Constant.messages.getString("exportreport.source.for.label"), Constant.messages.getString("exportreport.source.scandate.label"), Constant.messages.getString("exportreport.source.reportdate.label"), Constant.messages.getString("exportreport.source.scanver.label"), Constant.messages.getString("exportreport.source.reportver.label"), Constant.messages.getString("exportreport.source.description.label")));
                return ApiResponseElement.FAIL;
            }

            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.source.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
                logger.debug(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.source.label"), Constant.messages.getString("exportreport.message.console.info.status.unchecked")));
            }

            if (alertSeverityFlags.size() != extension.getAlertSeverity().size()) {
                logger.error(Constant.messages.getString("exportreport.message.console.error.risk.severity", Constant.messages.getString("exportreport.menu.risk.label"), alertSeverityFlags.size(), extension.getAlertSeverity().size(), Constant.messages.getString("exportreport.risk.severity.high.label"), Constant.messages.getString("exportreport.risk.severity.medium.label"), Constant.messages.getString("exportreport.risk.severity.low.label"), Constant.messages.getString("exportreport.risk.severity.info.label")));
                return ApiResponseElement.FAIL;
            }
            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.risk.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
            }

            if (!extension.validList(alertSeverityFlags)) {
                logger.warn(Constant.messages.getString("exportreport.message.console.error.valid.list", Constant.messages.getString("exportreport.menu.risk.label")));
                return ApiResponseElement.FAIL;
            }
            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.risk.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
            }

            if (alertDetailsFlags.size() != extension.extensionGetMaxList()) {
                logger.error(Constant.messages.getString("exportreport.message.console.error.details", Constant.messages.getString("exportreport.menu.details.label"), alertDetailsFlags.size(), extension.extensionGetMaxList(), Constant.messages.getString("exportreport.details.cweid.label"), Constant.messages.getString("exportreport.details.wascid.label"), Constant.messages.getString("exportreport.details.description.label"), Constant.messages.getString("exportreport.details.otherinfo.label"), Constant.messages.getString("exportreport.details.solution.label"), Constant.messages.getString("exportreport.details.reference.label"), Constant.messages.getString("exportreport.details.requestheader.label"), Constant.messages.getString("exportreport.details.responseheader.label"), Constant.messages.getString("exportreport.details.requestbody.label"), Constant.messages.getString("exportreport.details.responsebody.label")));
                return ApiResponseElement.FAIL;
            }
            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.length", Constant.messages.getString("exportreport.menu.details.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
            }

            if (!extension.validList(alertDetailsFlags)) {
                logger.warn(Constant.messages.getString("exportreport.message.console.error.valid.list", Constant.messages.getString("exportreport.menu.details.label")));
                return ApiResponseElement.FAIL;
            }
            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.content", Constant.messages.getString("exportreport.menu.details.label"), Constant.messages.getString("exportreport.message.console.info.status.valid")));
            }

            if (logger.isDebugEnabled()) {
                logger.debug(Constant.messages.getString("exportreport.message.console.info.pass.generate"));
            }

            ArrayList<String> alertSeverityTemp = extension.generateList(alertSeverityFlags, extension.getAlertSeverity());

            ArrayList<String> alertDetailsFull = new ArrayList<String>();
            alertDetailsFull.addAll(0, extension.getAlertDetails());
            alertDetailsFull.addAll(extension.getAlertDetails().size(), extension.getAlertAdditional());
            ArrayList<String> alertDetailsTemp = extension.generateList(alertDetailsFlags, alertDetailsFull);

            try {
                if (extension.generateReport(absolutePath, fileExtension, sourceDetails, alertSeverityTemp, alertDetailsTemp)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(Constant.messages.getString("exportreport.message.console.info.pass.path", absolutePath));
                    }
                    return ApiResponseElement.OK;
                }
                else {
                    return ApiResponseElement.FAIL;
                }
            } catch (Exception e) {
                logger.warn(Constant.messages.getString("exportreport.message.console.error.exception", e.getMessage()), e);
                return ApiResponseElement.FAIL;
            }
        default:
            throw new ApiException(Type.BAD_ACTION);
        }
    }

    @Override
    public ApiResponseList handleApiView(String name, JSONObject params) throws ApiException {
        if (logger.isDebugEnabled()) {
            logger.debug("Request for handleApiAction: " + name + " (params: " + params.toString() + ")");
        }
        switch (name) {
        case VIEW_FORMATS:
            final ApiResponseList resultList = new ApiResponseList(name);
            FileList fileList = extension.getFileList();
            for (FileType item : fileList) {
                if (item.isEnabled())
                    resultList.addItem(new ApiResponseElement("format", item.getExtension()));
            }
            return resultList;
        default:
            throw new ApiException(Type.BAD_VIEW);
        }
    }
}
