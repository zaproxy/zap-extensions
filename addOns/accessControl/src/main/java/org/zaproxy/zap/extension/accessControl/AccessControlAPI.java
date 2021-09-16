/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.accessControl;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.ParserConfigurationException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.accessControl.AccessControlScannerThread.AccessControlScanStartOptions;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ApiUtils;

public class AccessControlAPI extends ApiImplementor {
    private static final String PREFIX = "accessControl";

    private ExtensionAccessControl extension;

    private static ExtensionUserManagement usersExtension;

    private static final String ACTION_SCAN = "scan";
    private static final String ACTION_WRITE_HTML_REPORT = "writeHTMLreport";

    private static final String VIEW_GET_SCAN_PROGRESS = "getScanProgress";
    private static final String VIEW_GET_SCAN_STATUS = "getScanStatus";

    private static final String PARAM_CONTEXT_ID = "contextId";
    private static final String PARAM_USER_ID = "userId";
    private static final String PARAM_RAISE_ALERT = "raiseAlert";
    private static final String PARAM_ALERT_RISK_LEVEL = "alertRiskLevel";
    private static final String PARAM_UNAUTH_USER = "scanAsUnAuthUser";
    private static final String PARAM_FILENAME = "fileName";

    private static final Logger LOGGER = LogManager.getLogger(AccessControlAPI.class);

    /** Provided only for API client generator usage. */
    public AccessControlAPI() {
        this(null);
    }

    public AccessControlAPI(ExtensionAccessControl extension) {
        this.extension = extension;
        this.addApiAction(
                new ApiAction(
                        ACTION_SCAN,
                        new String[] {PARAM_CONTEXT_ID, PARAM_USER_ID},
                        new String[] {
                            PARAM_UNAUTH_USER, PARAM_RAISE_ALERT, PARAM_ALERT_RISK_LEVEL
                        }));

        this.addApiAction(
                new ApiAction(
                        ACTION_WRITE_HTML_REPORT, new String[] {PARAM_CONTEXT_ID, PARAM_FILENAME}));

        this.addApiView(new ApiView(VIEW_GET_SCAN_PROGRESS, new String[] {PARAM_CONTEXT_ID}));
        this.addApiView(new ApiView(VIEW_GET_SCAN_STATUS, new String[] {PARAM_CONTEXT_ID}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        ApiResponse result = null;

        switch (name) {
            case ACTION_SCAN:
                LOGGER.debug("Access control start scan called");

                AccessControlScanStartOptions startOptions = new AccessControlScanStartOptions();

                startOptions.setTargetContext(
                        ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID));

                Mode mode = Control.getSingleton().getMode();
                if (Mode.safe.equals(mode)) {
                    throw new ApiException(
                            ApiException.Type.MODE_VIOLATION,
                            Constant.messages.getString(
                                    "accessControl.scanOptions.error.mode.safe"));
                } else if (Mode.protect.equals(mode)
                        && !startOptions.getTargetContext().isInScope()) {
                    throw new ApiException(
                            ApiException.Type.MODE_VIOLATION,
                            Constant.messages.getString(
                                    "accessControl.scanOptions.error.mode.protected",
                                    startOptions.getTargetContext().getName()));
                }

                if (usersExtension == null) {
                    usersExtension =
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionUserManagement.class);
                }

                List<User> users = new ArrayList<>();

                String[] commaSeparatedUserIDs =
                        ApiUtils.getNonEmptyStringParam(params, PARAM_USER_ID).split("\\s*,\\s*");

                for (int i = 0; i < commaSeparatedUserIDs.length; i++) {
                    int userID;
                    try {
                        userID = Integer.parseInt(commaSeparatedUserIDs[i]);
                    } catch (NumberFormatException nfe) {
                        throw new ApiException(
                                ApiException.Type.ILLEGAL_PARAMETER,
                                "Failed to parse userID (int).",
                                nfe);
                    }
                    User userToAdd =
                            usersExtension
                                    .getContextUserAuthManager(
                                            startOptions.getTargetContext().getId())
                                    .getUserById(userID);
                    if (userToAdd != null) {
                        users.add(userToAdd);
                    } else {
                        throw new ApiException(
                                ApiException.Type.USER_NOT_FOUND,
                                "No user found for userID: " + userID);
                    }
                }

                startOptions.setTargetUsers(users);

                // Add unauthenticated user
                if (params.optBoolean(PARAM_UNAUTH_USER, false)) {
                    startOptions.getTargetUsers().add(null);
                }

                startOptions.setRaiseAlerts(params.optBoolean(PARAM_RAISE_ALERT, true));

                startOptions.setAlertRiskLevel(
                        params.optInt(PARAM_ALERT_RISK_LEVEL, Alert.RISK_HIGH));
                if (!(startOptions.getAlertRiskLevel() >= Alert.RISK_INFO
                        && startOptions.getAlertRiskLevel() <= Alert.RISK_HIGH)) {
                    throw new ApiException(
                            ApiException.Type.ILLEGAL_PARAMETER,
                            "The parsed Alert Risk Level was outside the range: "
                                    + Alert.RISK_INFO
                                    + " to "
                                    + Alert.RISK_HIGH);
                }

                extension.startScan(startOptions);

                result = ApiResponseElement.OK;
                break;

            case ACTION_WRITE_HTML_REPORT:
                LOGGER.debug("Write HTML report called");

                File reportFile = new File(params.getString(PARAM_FILENAME));

                try {
                    extension.generateAccessControlReport(
                            ApiUtils.getIntParam(params, PARAM_CONTEXT_ID), reportFile);
                    result = new ApiResponseElement(name, "OK");
                } catch (ParserConfigurationException pce) {
                    String pceMessage = "Failed to generate access control report: ";
                    LOGGER.error(pceMessage, pce);
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, pceMessage, pce);
                }

                // Have to add the check because ReportGenerator.XMLToHtml() won't raise an
                // exception
                if (!reportFile.exists() || !reportFile.canWrite()) {
                    String writeFailedMessage =
                            "Error writing report to file " + reportFile.getPath();
                    LOGGER.error(writeFailedMessage);
                    throw new ApiException(ApiException.Type.INTERNAL_ERROR, writeFailedMessage);
                }
                break;
            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }

        return result;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result;
        int contextId;
        switch (name) {
            case VIEW_GET_SCAN_PROGRESS:
                LOGGER.debug("Access control get scan progress called");

                contextId = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID).getId();

                String scanStatus;
                try {
                    scanStatus = String.valueOf(extension.getScanProgress(contextId));
                } catch (IllegalStateException ise) {
                    throw new ApiException(
                            ApiException.Type.DOES_NOT_EXIST,
                            "Failed to obtain scan progress for contextId: " + contextId);
                }
                result = new ApiResponseElement(name, scanStatus);
                break;
            case VIEW_GET_SCAN_STATUS:
                LOGGER.debug("Access control get scan status called");

                contextId = ApiUtils.getContextByParamId(params, PARAM_CONTEXT_ID).getId();

                result = new ApiResponseElement(name, extension.getScanStatus(contextId));
                break;
            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }

        return result;
    }
}
