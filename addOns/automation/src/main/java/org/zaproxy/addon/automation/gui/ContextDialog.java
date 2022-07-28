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
package org.zaproxy.addon.automation.gui;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ContextDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.context.tab.context",
        "automation.dialog.context.tab.include",
        "automation.dialog.context.tab.exclude"
    };

    private static final String TITLE = "automation.dialog.context.title";
    private static final String NAME_PARAM = "automation.dialog.context.name";
    private static final String URLS_PARAM = "automation.dialog.context.urls";
    private static final String INCLUDE_PARAM = "automation.dialog.context.include";
    private static final String EXCLUDE_PARAM = "automation.dialog.context.exclude";

    private boolean isNew = false;
    private EnvironmentDialog envDialog;
    private ContextWrapper.Data context;

    public ContextDialog(EnvironmentDialog owner) {
        this(owner, null);
    }

    public ContextDialog(EnvironmentDialog owner, ContextWrapper.Data context) {
        super(owner, TITLE, DisplayUtils.getScaledDimension(400, 300), TAB_LABELS);
        this.envDialog = owner;
        if (context == null) {
            context = new ContextWrapper.Data();
            this.isNew = true;
        }
        this.context = context;

        this.addTextField(0, NAME_PARAM, context.getName());
        this.addMultilineField(0, URLS_PARAM, listToString(context.getUrls()));

        this.addMultilineField(1, INCLUDE_PARAM, listToString(context.getIncludePaths()));

        this.addMultilineField(2, EXCLUDE_PARAM, listToString(context.getExcludePaths()));
    }

    private String listToString(List<String> list) {
        if (list != null) {
            return StringUtils.join(list, "\n");
        }
        return "";
    }

    private List<String> stringParamToList(String param) {
        // Return a list of the trimmed and non empty strings
        return Arrays.asList(this.getStringValue(param).split("\n")).stream()
                .map(String::trim)
                .filter(item -> !item.isEmpty())
                .collect(Collectors.toList());
    }

    @Override
    public void save() {
        this.context.setName(this.getStringValue(NAME_PARAM).trim());
        this.context.setUrls(stringParamToList(URLS_PARAM));
        this.context.setIncludePaths(stringParamToList(INCLUDE_PARAM));
        this.context.setExcludePaths(stringParamToList(EXCLUDE_PARAM));
        if (this.isNew) {
            envDialog.addContext(context);
        }
    }

    @Override
    public String validateFields() {
        if (this.getStringValue(NAME_PARAM).trim().isEmpty()) {
            return Constant.messages.getString("automation.dialog.context.error.badname");
        }
        List<String> urls = stringParamToList(URLS_PARAM);
        if (urls.isEmpty()) {
            return Constant.messages.getString("automation.dialog.context.error.nourls");
        }
        for (String str : urls) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    new URI(str, true);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.badurl", str);
                }
            }
        }
        for (String str : stringParamToList(INCLUDE_PARAM)) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    Pattern.compile(str);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.incregex", str);
                }
            }
        }
        for (String str : stringParamToList(EXCLUDE_PARAM)) {
            if (!str.contains("${")) {
                // Can only validate strings that dont contain env vars
                try {
                    Pattern.compile(str);
                } catch (Exception e) {
                    return Constant.messages.getString(
                            "automation.dialog.context.error.excregex", str);
                }
            }
        }
        return null;
    }
}
