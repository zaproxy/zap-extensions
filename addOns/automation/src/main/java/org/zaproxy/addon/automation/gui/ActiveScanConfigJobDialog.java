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
package org.zaproxy.addon.automation.gui;

import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.ActiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.ActiveScanConfigJob.InputVectors;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ActiveScanConfigJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params", "automation.dialog.ascanconfig.tab.iv"
    };

    private static final String TITLE = "automation.dialog.ascanconfig.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";

    private static final String MAX_RULE_DURATION_PARAM =
            "automation.dialog.ascanconfig.maxruleduration";
    private static final String MAX_SCAN_DURATION_PARAM =
            "automation.dialog.ascanconfig.maxscanduration";
    private static final String MAX_ALERTS_PER_RULE_PARAM =
            "automation.dialog.ascanconfig.maxalertsperrule";
    private static final String DEFAULT_POLICY_PARAM =
            "automation.dialog.ascanconfig.defaultpolicy";
    private static final String HANDLE_ANTI_CSRF_PARAM =
            "automation.dialog.ascanconfig.handleanticsrf";
    private static final String INJECT_SCAN_RULE_ID_PARAM =
            "automation.dialog.ascanconfig.injectid";
    private static final String THREADS_PER_HOST_PARAM = "automation.dialog.ascanconfig.threads";

    private static final String QUERY_PARAM = "automation.dialog.ascanconfig.iv.query";
    private static final String QUERY_ADD_PARAM = "automation.dialog.ascanconfig.iv.query.addparam";
    private static final String QUERY_ODATA_PARAM = "automation.dialog.ascanconfig.iv.query.odata";

    private static final String POST_PARAM = "automation.dialog.ascanconfig.iv.post";
    private static final String POST_MULTIPART_PARAM =
            "automation.dialog.ascanconfig.iv.post.multipart";
    private static final String POST_XML_PARAM = "automation.dialog.ascanconfig.iv.post.xml";
    private static final String POST_JSON_PARAM = "automation.dialog.ascanconfig.iv.post.json";
    private static final String POST_JSON_NULLS_PARAM =
            "automation.dialog.ascanconfig.iv.post.json.nulls";
    private static final String POST_GWT_PARAM = "automation.dialog.ascanconfig.iv.post.gwt";
    private static final String POST_DWR_PARAM = "automation.dialog.ascanconfig.iv.post.dwr";

    private static final String PATH_PARAM = "automation.dialog.ascanconfig.iv.path";

    private static final String HEADERS_PARAM = "automation.dialog.ascanconfig.iv.headers";
    private static final String HEADERS_ALL_REQUESTS_PARAM =
            "automation.dialog.ascanconfig.iv.headers.allrequests";

    private static final String COOKIE_PARAM = "automation.dialog.ascanconfig.iv.cookie";
    private static final String COOKIE_ENCODE_PARAM =
            "automation.dialog.ascanconfig.iv.cookie.encode";

    private static final String SCRIPTS_PARAM = "automation.dialog.ascanconfig.iv.scripts";

    private ActiveScanConfigJob job;

    public ActiveScanConfigJobDialog(ActiveScanConfigJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 550),
                TAB_LABELS);
        this.job = job;

        addTextField(0, NAME_PARAM, job.getData().getName());

        ActiveScanConfigJob.Parameters parameters = job.getParameters();
        addNumberField(
                0,
                MAX_RULE_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(parameters.getMaxRuleDurationInMins()));

        addNumberField(
                0,
                MAX_SCAN_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(parameters.getMaxScanDurationInMins()));

        addNumberField(
                0,
                MAX_ALERTS_PER_RULE_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(parameters.getMaxAlertsPerRule()));

        addTextField(0, DEFAULT_POLICY_PARAM, parameters.getDefaultPolicy());

        addCheckBoxField(
                0, HANDLE_ANTI_CSRF_PARAM, JobUtils.unBox(parameters.getHandleAntiCSRFTokens()));

        addCheckBoxField(
                0,
                INJECT_SCAN_RULE_ID_PARAM,
                JobUtils.unBox(parameters.getInjectPluginIdInHeader()));

        addNumberField(
                0,
                THREADS_PER_HOST_PARAM,
                1,
                Integer.MAX_VALUE,
                JobUtils.unBox(parameters.getThreadPerHost()));

        addPadding(0);

        InputVectors iv = job.getData().getInputVectors();
        InputVectors.UrlQueryStringAndDataDrivenNodes queryOptions =
                iv.getUrlQueryStringAndDataDrivenNodes();
        if (queryOptions == null) {
            queryOptions = new InputVectors.UrlQueryStringAndDataDrivenNodes();
            iv.setUrlQueryStringAndDataDrivenNodes(queryOptions);
        }
        addCheckBoxField(1, QUERY_PARAM, queryOptions.isEnabled());
        addCheckBoxField(1, QUERY_ADD_PARAM, queryOptions.isAddParam());
        addCheckBoxField(1, QUERY_ODATA_PARAM, queryOptions.isOdata());

        InputVectors.PostData postOptions = iv.getPostData();
        if (postOptions == null) {
            postOptions = new InputVectors.PostData();
            iv.setPostData(postOptions);
        }
        addCheckBoxField(1, POST_PARAM, postOptions.isEnabled());
        addCheckBoxField(1, POST_MULTIPART_PARAM, postOptions.isMultiPartFormData());
        addCheckBoxField(1, POST_XML_PARAM, postOptions.isXml());
        InputVectors.PostData.Json jsonOptions = postOptions.getJson();
        if (jsonOptions == null) {
            jsonOptions = new InputVectors.PostData.Json();
            postOptions.setJson(jsonOptions);
        }
        addCheckBoxField(1, POST_JSON_PARAM, jsonOptions.isEnabled());
        addCheckBoxField(1, POST_JSON_NULLS_PARAM, jsonOptions.isScanNullValues());

        addCheckBoxField(1, POST_GWT_PARAM, postOptions.isGoogleWebToolkit());
        addCheckBoxField(1, POST_DWR_PARAM, postOptions.isDirectWebRemoting());

        addCheckBoxField(1, PATH_PARAM, iv.isUrlPath());

        InputVectors.HttpHeaders headersOptions = iv.getHttpHeaders();
        if (headersOptions == null) {
            headersOptions = new InputVectors.HttpHeaders();
            iv.setHttpHeaders(headersOptions);
        }
        addCheckBoxField(1, HEADERS_PARAM, headersOptions.isEnabled());
        addCheckBoxField(1, HEADERS_ALL_REQUESTS_PARAM, headersOptions.isAllRequests());

        InputVectors.CookieData cookieOptions = iv.getCookieData();
        if (cookieOptions == null) {
            cookieOptions = new InputVectors.CookieData();
            iv.setCookieData(cookieOptions);
        }
        addCheckBoxField(1, COOKIE_PARAM, cookieOptions.isEnabled());
        addCheckBoxField(1, COOKIE_ENCODE_PARAM, cookieOptions.isEncodeCookieValues());

        addCheckBoxField(1, SCRIPTS_PARAM, iv.isScripts());

        addPadding(1);
    }

    @Override
    public void save() {
        job.getData().setName(getStringValue(NAME_PARAM));

        ActiveScanConfigJob.Parameters parameters = job.getParameters();
        parameters.setMaxRuleDurationInMins(getIntValue(MAX_RULE_DURATION_PARAM));
        parameters.setMaxScanDurationInMins(getIntValue(MAX_SCAN_DURATION_PARAM));
        parameters.setMaxAlertsPerRule(getIntValue(MAX_ALERTS_PER_RULE_PARAM));
        parameters.setDefaultPolicy(getStringValue(DEFAULT_POLICY_PARAM));
        parameters.setHandleAntiCSRFTokens(getBoolValue(HANDLE_ANTI_CSRF_PARAM));
        parameters.setInjectPluginIdInHeader(getBoolValue(INJECT_SCAN_RULE_ID_PARAM));
        parameters.setThreadPerHost(getIntValue(THREADS_PER_HOST_PARAM));

        InputVectors iv = job.getData().getInputVectors();
        InputVectors.UrlQueryStringAndDataDrivenNodes queryOptions =
                iv.getUrlQueryStringAndDataDrivenNodes();
        queryOptions.setEnabled(getBoolValue(QUERY_PARAM));
        queryOptions.setAddParam(getBoolValue(QUERY_ADD_PARAM));
        queryOptions.setOdata(getBoolValue(QUERY_ODATA_PARAM));

        InputVectors.PostData postOptions = iv.getPostData();
        postOptions.setEnabled(getBoolValue(POST_PARAM));
        postOptions.setMultiPartFormData(getBoolValue(POST_MULTIPART_PARAM));
        postOptions.setXml(getBoolValue(POST_XML_PARAM));
        InputVectors.PostData.Json jsonOptions = postOptions.getJson();
        jsonOptions.setEnabled(getBoolValue(POST_JSON_PARAM));
        jsonOptions.setScanNullValues(getBoolValue(POST_JSON_NULLS_PARAM));

        postOptions.setGoogleWebToolkit(getBoolValue(POST_GWT_PARAM));
        postOptions.setDirectWebRemoting(getBoolValue(POST_DWR_PARAM));

        iv.setUrlPath(getBoolValue(PATH_PARAM));

        InputVectors.HttpHeaders headersOptions = iv.getHttpHeaders();
        headersOptions.setEnabled(getBoolValue(HEADERS_PARAM));
        headersOptions.setAllRequests(getBoolValue(HEADERS_ALL_REQUESTS_PARAM));

        InputVectors.CookieData cookieOptions = iv.getCookieData();
        cookieOptions.setEnabled(getBoolValue(COOKIE_PARAM));
        cookieOptions.setEncodeCookieValues(getBoolValue(COOKIE_ENCODE_PARAM));

        iv.setScripts(getBoolValue(SCRIPTS_PARAM));

        job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
