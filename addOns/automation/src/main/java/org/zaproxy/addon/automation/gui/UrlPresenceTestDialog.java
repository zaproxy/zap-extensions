/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.awt.Component;
import java.net.URL;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.swing.JTextField;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest.OnFail;
import org.zaproxy.addon.automation.tests.UrlPresenceTest;
import org.zaproxy.addon.automation.tests.UrlPresenceTest.Operator;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class UrlPresenceTestDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;
    private static final String TITLE = "automation.dialog.urlpresencetest.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String URL_PARAM = "automation.dialog.urlpresencetest.url";
    private static final String ON_FAIL_PARAM = "automation.dialog.urlpresencetest.onfail";
    private static final String OPERATOR_PARAM = "automation.dialog.urlpresencetest.operator";
    private static final String REQUEST_HEADER_REGEX =
            "automation.dialog.urlpresencetest.requestheaderregex";
    private static final String RESPONSE_HEADER_REGEX =
            "automation.dialog.urlpresencetest.responseheaderregex";
    private static final String REQUEST_BODY_REGEX =
            "automation.dialog.urlpresencetest.requestbodyregex";
    private static final String RESPONSE_BODY_REGEX =
            "automation.dialog.urlpresencetest.responsebodyregex";

    private static final String ERROR_URL_EMPTY =
            "automation.dialog.urlpresencetest.error.url.empty";
    private static final String ERROR_URL_INVALID =
            "automation.dialog.urlpresencetest.error.url.invalid";
    private static final String ERROR_INVALID_REQUEST_HEADER_REGEX =
            "automation.dialog.urlpresencetest.error.requestheaderregex.invalid";
    private static final String ERROR_INVALID_RESPONSE_HEADER_REGEX =
            "automation.dialog.urlpresencetest.error.responseheaderregex.invalid";
    private static final String ERROR_INVALID_REQUEST_BODY_REGEX =
            "automation.dialog.urlpresencetest.error.requestbodyregex.invalid";
    private static final String ERROR_INVALID_RESPONSE_BODY_REGEX =
            "automation.dialog.urlpresencetest.error.responsebodyregex.invalid";

    private UrlPresenceTest test;

    public UrlPresenceTestDialog(UrlPresenceTest test) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 350));
        this.test = test;
        this.addTextField(NAME_PARAM, this.test.getName());

        this.addComboField(
                ON_FAIL_PARAM,
                Arrays.asList(OnFail.values()).stream()
                        .map(OnFail::toString)
                        .toArray(String[]::new),
                this.test.getData().getOnFail().toString());

        this.addNodeSelectField(URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(this.test.getData().getUrl());
        }

        this.addComboField(
                OPERATOR_PARAM,
                Arrays.asList(Operator.values()).stream()
                        .map(Operator::getI18nString)
                        .toArray(String[]::new),
                test.getData().getOperator());

        this.addTextField(REQUEST_HEADER_REGEX, this.test.getData().getRequestHeaderRegex());
        this.addTextField(RESPONSE_HEADER_REGEX, this.test.getData().getResponseHeaderRegex());
        this.addTextField(REQUEST_BODY_REGEX, this.test.getData().getRequestBodyRegex());
        this.addTextField(RESPONSE_BODY_REGEX, this.test.getData().getResponseBodyRegex());

        this.addPadding();
    }

    @Override
    public void save() {
        this.test.getData().setName(this.getStringValue(NAME_PARAM));
        this.test.getData().setUrl(this.getStringValue(URL_PARAM));
        this.test.getData().setOperator(this.getStringValue(OPERATOR_PARAM));
        this.test.getData().setRequestHeaderRegex(this.getStringValue(REQUEST_HEADER_REGEX));
        this.test.getData().setResponseHeaderRegex(this.getStringValue(RESPONSE_HEADER_REGEX));
        this.test.getData().setRequestBodyRegex(this.getStringValue(REQUEST_BODY_REGEX));
        this.test.getData().setResponseBodyRegex(this.getStringValue(RESPONSE_BODY_REGEX));
        this.test.getData().setOnFail(OnFail.i18nToOnFail(this.getStringValue(ON_FAIL_PARAM)));
        this.test.getJob().getPlan().setChanged();
    }

    @Override
    public String validateFields() {
        String url = this.getStringValue(URL_PARAM);
        if (url == null || url.isEmpty()) {
            return Constant.messages.getString(ERROR_URL_EMPTY);
        }

        URL uri = null;
        try {
            uri = new URL(url);
            uri.toURI();
        } catch (Exception e) {
            return Constant.messages.getString(ERROR_URL_INVALID, url, e.getMessage());
        }

        String requestHeaderRegex = this.getStringValue(REQUEST_HEADER_REGEX);
        String requestBodyRegex = this.getStringValue(REQUEST_BODY_REGEX);
        String responseHeaderRegex = this.getStringValue(RESPONSE_HEADER_REGEX);
        String responseBodyRegex = this.getStringValue(RESPONSE_BODY_REGEX);

        try {
            Pattern.compile(requestHeaderRegex);
        } catch (Exception e) {
            return Constant.messages.getString(
                    ERROR_INVALID_REQUEST_HEADER_REGEX, requestHeaderRegex, e.getMessage());
        }

        try {
            Pattern.compile(requestBodyRegex);
        } catch (Exception e) {
            return Constant.messages.getString(
                    ERROR_INVALID_REQUEST_BODY_REGEX, requestBodyRegex, e.getMessage());
        }
        try {
            Pattern.compile(responseHeaderRegex);
        } catch (Exception e) {
            return Constant.messages.getString(
                    ERROR_INVALID_RESPONSE_HEADER_REGEX, responseHeaderRegex, e.getMessage());
        }
        try {
            Pattern.compile(responseBodyRegex);
        } catch (Exception e) {
            return Constant.messages.getString(
                    ERROR_INVALID_RESPONSE_BODY_REGEX, responseBodyRegex, e.getMessage());
        }
        return null;
    }
}
