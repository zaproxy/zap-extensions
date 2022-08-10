/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer;

import java.awt.Window;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ReplaceRuleAddDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String FIRST_TAB = "replacer.tab.rule";
    private static final String INITIATORS_TAB = "replacer.tab.init";

    private static final String[] ADV_TAB_LABELS = {FIRST_TAB, INITIATORS_TAB};

    protected static final String DESC_FIELD = "replacer.label.desc";
    protected static final String MATCH_STR_FIELD = "replacer.label.matchstr";
    protected static final String MATCH_TYPE_FIELD = "replacer.label.matchtype";
    protected static final String REGEX_FIELD = "replacer.label.regex";
    protected static final String REPLACEMENT_FIELD = "replacer.label.replace";
    protected static final String ENABLE_FIELD = "replacer.label.enable";
    protected static final String INIT_TYPE_SUMMARY_FIELD = "replacer.label.initsummary";

    protected static final String INIT_TYPE_ALL_FIELD = "replacer.label.init.all";
    protected static final String INIT_TYPE_PROXY_FIELD = "replacer.label.init.proxy";
    protected static final String INIT_TYPE_SPIDER_FIELD = "replacer.label.init.spider";
    protected static final String INIT_TYPE_SCANNER_FIELD = "replacer.label.init.scanner";
    protected static final String INIT_TYPE_BRUTE_FIELD = "replacer.label.init.brute";
    protected static final String INIT_TYPE_FUZZER_FIELD = "replacer.label.init.fuzzer";
    protected static final String INIT_TYPE_SPIDER_AJAX_FIELD = "replacer.label.init.spiderajax";
    protected static final String INIT_TYPE_AUTH_FIELD = "replacer.label.init.auth";
    protected static final String INIT_TYPE_AC_FIELD = "replacer.label.init.ac";
    protected static final String INIT_TYPE_USER_FIELD = "replacer.label.init.user";
    protected static final String INIT_TYPE_TOKEN_GEN_FIELD = "replacer.label.init.tokengen";

    private ReplacerParam replacerParam;
    private ReplacerParamRule rule;
    private OptionsReplacerTableModel replacerModel;

    public ReplaceRuleAddDialog(
            Window owner,
            String title,
            ReplacerParam replacerParam,
            OptionsReplacerTableModel replacerModel) {
        super(owner, title, DisplayUtils.getScaledDimension(500, 350), ADV_TAB_LABELS, true);
        this.replacerParam = replacerParam;
        this.replacerModel = replacerModel;
        initFields();
    }

    private void initFields() {

        String selectedStr = this.getStringValue(MATCH_TYPE_FIELD);
        MatchType selectedMatchType = this.getSelectedMatchType();

        this.removeAllFields();
        this.addTextField(0, DESC_FIELD, "");
        this.addComboField(0, MATCH_TYPE_FIELD, getMatchTypes(), selectedStr);

        if (ReplacerParamRule.MatchType.REQ_HEADER.equals(selectedMatchType)) {
            this.addComboField(0, MATCH_STR_FIELD, getDefaultRequestHeaders(), "", true);
            this.addCheckBoxField(0, REGEX_FIELD, false);
            // Only support exact matches with headers
            this.getField(REGEX_FIELD).setEnabled(false);
        } else if (ReplacerParamRule.MatchType.RESP_HEADER.equals(selectedMatchType)) {
            this.addComboField(0, MATCH_STR_FIELD, getDefaultResponseHeaders(), "", true);
            this.addCheckBoxField(0, REGEX_FIELD, false);
            // Only support exact matches with headers
            this.getField(REGEX_FIELD).setEnabled(false);
        } else {
            this.addTextField(0, MATCH_STR_FIELD, "");
            this.addCheckBoxField(0, REGEX_FIELD, false);
        }

        this.addTextField(0, REPLACEMENT_FIELD, "");
        this.addReadOnlyField(0, INIT_TYPE_SUMMARY_FIELD, "", false);
        this.addCheckBoxField(0, ENABLE_FIELD, false);
        this.addPadding(0);

        this.addCheckBoxField(1, INIT_TYPE_ALL_FIELD, true);
        this.addCheckBoxField(1, INIT_TYPE_PROXY_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_SPIDER_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_SCANNER_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_BRUTE_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_FUZZER_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_SPIDER_AJAX_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_AUTH_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_AC_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_USER_FIELD, false);
        this.addCheckBoxField(1, INIT_TYPE_TOKEN_GEN_FIELD, false);
        this.addPadding(1);

        // Set before adding the listener so we don't get in a loop
        this.setRule(rule, selectedMatchType);

        this.addFieldListener(
                MATCH_TYPE_FIELD,
                e -> {
                    saveImpl();
                    initFields();
                });
        this.addFieldListener(INIT_TYPE_ALL_FIELD, e -> setUpInitiatorFields());
    }

    private void setUpInitiatorFields() {
        boolean bool = !getBoolValue(INIT_TYPE_ALL_FIELD);
        if (bool) {
            this.setFieldValue(
                    INIT_TYPE_SUMMARY_FIELD,
                    Constant.messages.getString("replacer.label.initsummary.tab"));
        } else {
            this.setFieldValue(
                    INIT_TYPE_SUMMARY_FIELD,
                    Constant.messages.getString("replacer.label.initsummary.all"));
        }

        getField(INIT_TYPE_PROXY_FIELD).setEnabled(bool);
        getField(INIT_TYPE_SPIDER_FIELD).setEnabled(bool);
        getField(INIT_TYPE_SCANNER_FIELD).setEnabled(bool);
        getField(INIT_TYPE_BRUTE_FIELD).setEnabled(bool);
        getField(INIT_TYPE_FUZZER_FIELD).setEnabled(bool);
        getField(INIT_TYPE_SPIDER_AJAX_FIELD).setEnabled(bool);
        getField(INIT_TYPE_AUTH_FIELD).setEnabled(bool);
        getField(INIT_TYPE_AC_FIELD).setEnabled(bool);
        getField(INIT_TYPE_USER_FIELD).setEnabled(bool);
        getField(INIT_TYPE_TOKEN_GEN_FIELD).setEnabled(bool);
    }

    public ReplacerParamRule getRule() {
        return rule;
    }

    public void setRule(ReplacerParamRule rule) {
        initFields();
        this.setRule(rule, null);
    }

    public OptionsReplacerTableModel getReplacerModel() {
        return this.replacerModel;
    }

    public ReplacerParam getReplacerParam() {
        return replacerParam;
    }

    public void setReplacerParam(ReplacerParam replacerParam) {
        this.replacerParam = replacerParam;
    }

    private void setRule(ReplacerParamRule rule, MatchType selectedMatchType) {
        this.rule = rule;
        if (rule != null) {
            this.setFieldValue(DESC_FIELD, rule.getDescription());
            if (selectedMatchType != null) {
                // overrides the one set
                this.setFieldValue(MATCH_TYPE_FIELD, matchTypeToStr(selectedMatchType));
            } else {
                this.setFieldValue(MATCH_TYPE_FIELD, matchTypeToStr(rule.getMatchType()));
            }
            this.setFieldValue(MATCH_STR_FIELD, rule.getMatchString());
            this.setFieldValue(REGEX_FIELD, rule.isMatchRegex());
            this.setFieldValue(REPLACEMENT_FIELD, rule.getReplacement());
            this.setFieldValue(ENABLE_FIELD, rule.isEnabled());
            if (rule.appliesToAllInitiators()) {
                this.setFieldValue(INIT_TYPE_ALL_FIELD, true);
            } else {
                this.setFieldValue(INIT_TYPE_ALL_FIELD, false);
                this.setFieldValue(
                        INIT_TYPE_PROXY_FIELD,
                        rule.getInitiators().contains(HttpSender.PROXY_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_SPIDER_FIELD,
                        rule.getInitiators().contains(HttpSender.SPIDER_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_SCANNER_FIELD,
                        rule.getInitiators().contains(HttpSender.ACTIVE_SCANNER_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_BRUTE_FIELD,
                        rule.getInitiators().contains(HttpSender.FORCED_BROWSE_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_FUZZER_FIELD,
                        rule.getInitiators().contains(HttpSender.FUZZER_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_SPIDER_AJAX_FIELD,
                        rule.getInitiators().contains(HttpSender.AJAX_SPIDER_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_AUTH_FIELD,
                        rule.getInitiators().contains(HttpSender.AUTHENTICATION_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_AC_FIELD,
                        rule.getInitiators().contains(HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_USER_FIELD,
                        rule.getInitiators().contains(HttpSender.MANUAL_REQUEST_INITIATOR));
                this.setFieldValue(
                        INIT_TYPE_TOKEN_GEN_FIELD,
                        rule.getInitiators().contains(HttpSender.TOKEN_GENERATOR_INITIATOR));
            }
        }
        setUpInitiatorFields();
    }

    @Override
    public void cancelPressed() {
        super.cancelPressed();
        this.rule = null;
    }

    @Override
    public void save() {
        saveImpl();
    }

    public void saveImpl() {
        List<Integer> initiators = null;
        if (Boolean.FALSE.equals(getBoolValue(INIT_TYPE_ALL_FIELD))) {
            initiators = new ArrayList<>();
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_PROXY_FIELD))) {
                initiators.add(HttpSender.PROXY_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_SPIDER_FIELD))) {
                initiators.add(HttpSender.SPIDER_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_SCANNER_FIELD))) {
                initiators.add(HttpSender.ACTIVE_SCANNER_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_BRUTE_FIELD))) {
                initiators.add(HttpSender.FORCED_BROWSE_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_FUZZER_FIELD))) {
                initiators.add(HttpSender.FUZZER_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_SPIDER_AJAX_FIELD))) {
                initiators.add(HttpSender.AJAX_SPIDER_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_AUTH_FIELD))) {
                initiators.add(HttpSender.AUTHENTICATION_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_AC_FIELD))) {
                initiators.add(HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_USER_FIELD))) {
                initiators.add(HttpSender.MANUAL_REQUEST_INITIATOR);
            }
            if (Boolean.TRUE.equals(getBoolValue(INIT_TYPE_TOKEN_GEN_FIELD))) {
                initiators.add(HttpSender.TOKEN_GENERATOR_INITIATOR);
            }
        }

        rule =
                new ReplacerParamRule(
                        this.getStringValue(DESC_FIELD),
                        this.getSelectedMatchType(),
                        this.getStringValue(MATCH_STR_FIELD),
                        this.getBoolValue(REGEX_FIELD),
                        this.getStringValue(REPLACEMENT_FIELD),
                        initiators,
                        this.getBoolValue(ENABLE_FIELD));
    }

    protected String checkIfUnique() {
        if (this.replacerModel.containsRule(this.getStringValue(DESC_FIELD))) {
            return Constant.messages.getString("replacer.add.warning.existdesc");
        }
        return null;
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(DESC_FIELD)) {
            return Constant.messages.getString("replacer.add.warning.nodesc");
        }
        if (this.isEmptyField(MATCH_STR_FIELD)) {
            return Constant.messages.getString("replacer.add.warning.nomatch");
        }
        if (Boolean.TRUE.equals(this.getBoolValue(REGEX_FIELD))) {
            // Check the regex is valid
            try {
                Pattern.compile(this.getStringValue(MATCH_STR_FIELD));
            } catch (PatternSyntaxException e) {
                return Constant.messages.getString("replacer.add.warning.badregex");
            }
        }
        return checkIfUnique();
    }

    private String matchTypeToStr(ReplacerParamRule.MatchType matchType) {
        return (Constant.messages.getString(
                "replacer.matchtype." + matchType.name().toLowerCase()));
    }

    private List<String> getMatchTypes() {
        List<String> list = new ArrayList<>();
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.REQ_HEADER));
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.REQ_HEADER_STR));
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.REQ_BODY_STR));
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.RESP_HEADER));
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.RESP_HEADER_STR));
        list.add(matchTypeToStr(ReplacerParamRule.MatchType.RESP_BODY_STR));
        return list;
    }

    private List<String> getDefaultRequestHeaders() {
        // Taken from https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
        List<String> list = new ArrayList<>();
        list.add("Accept");
        list.add("Accept-Charset");
        list.add("Accept-Datetime");
        list.add("Accept-Encoding");
        list.add("Accept-Language");
        list.add("Authorization");
        list.add("Cache-Control");
        list.add("Connection");
        list.add("Content-Length");
        list.add("Content-MD5");
        list.add("Content-Type");
        list.add("Cookie");
        list.add("Date");
        list.add("Expect");
        list.add("Forwarded");
        list.add("From");
        list.add("Host");
        list.add("If-Match");
        list.add("If-Modified-Since");
        list.add("Permanent");
        list.add("If-None-Match");
        list.add("If-Range");
        list.add("If-Unmodified-Since");
        list.add("Max-Forwards");
        list.add("Origin");
        list.add("Pragma");
        list.add("Proxy-Authorization");
        list.add("Range");
        list.add("Referer");
        list.add("TE");
        list.add("Upgrade");
        list.add("User-Agent");
        list.add("Via");
        list.add("Warning");
        // Common non-standard request fields
        list.add("XMLHttpRequest");
        list.add("DNT");
        list.add("X-Forwarded-For");
        list.add("X-Forwarded-Host");
        list.add("X-Forwarded-Proto");
        list.add("Front-End-Https");
        list.add("X-Http-Method-Override");
        list.add("X-ATT-DeviceId");
        list.add("X-Wap-Profile");
        list.add("Proxy-Connection");
        list.add("X-UIDH");
        list.add("X-Csrf-Token");
        list.add("X-Request-ID");
        list.add("X-Correlation-ID");
        Collections.sort(list);
        return list;
    }

    private List<String> getDefaultResponseHeaders() {
        // Taken from https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
        List<String> list = new ArrayList<>();
        list.add("Access-Control-Allow-Origin");
        list.add("Accept-Patch");
        list.add("Accept-Ranges");
        list.add("Age");
        list.add("Allow");
        list.add("Alt-Svc");
        list.add("Cache-Control");
        list.add("Connection");
        list.add("Content-Disposition");
        list.add("Content-Encoding");
        list.add("Content-Language");
        list.add("Content-Length");
        list.add("Content-Location");
        list.add("Content-MD5");
        list.add("Content-Range");
        list.add("Content-Type");
        list.add("Date");
        list.add("ETag");
        list.add("Expires");
        list.add("Last-Modified");
        list.add("Link");
        list.add("Location");
        list.add("P3P");
        list.add("Pragma");
        list.add("Proxy-Authenticate");
        list.add("Public-Key-Pins");
        list.add("Refresh");
        list.add("Retry-After");
        list.add("Server");
        list.add("Set-Cookie");
        list.add("Status");
        list.add("Strict-Transport-Security");
        list.add("Trailer");
        list.add("Transfer-Encoding");
        list.add("TSV");
        list.add("Uprade");
        list.add("Vary");
        list.add("Via");
        list.add("Warning");
        list.add("WWW-Authenticate");
        list.add("X-Frame-Options");
        // Common non-standard response fields
        list.add("X-XSS-Protection");
        list.add("Content-Security-Policy");
        list.add("X-Content-Security-Policy");
        list.add("X-WebKit-CSP");
        list.add("X-Content-Type-Options");
        list.add("X-Powered-By");
        list.add("X-UA-Compatible");
        list.add("X-Content-Duration");
        list.add("X-Request-ID");
        list.add("X-Correlation-ID");
        Collections.sort(list);
        return list;
    }

    private ReplacerParamRule.MatchType getSelectedMatchType() {
        String selectedStr = this.getStringValue(MATCH_TYPE_FIELD);
        if (matchTypeToStr(ReplacerParamRule.MatchType.REQ_HEADER).equals(selectedStr)) {
            return ReplacerParamRule.MatchType.REQ_HEADER;
        } else if (matchTypeToStr(ReplacerParamRule.MatchType.REQ_HEADER_STR).equals(selectedStr)) {
            return ReplacerParamRule.MatchType.REQ_HEADER_STR;
        } else if (matchTypeToStr(ReplacerParamRule.MatchType.REQ_BODY_STR).equals(selectedStr)) {
            return ReplacerParamRule.MatchType.REQ_BODY_STR;
        } else if (matchTypeToStr(ReplacerParamRule.MatchType.RESP_HEADER).equals(selectedStr)) {
            return ReplacerParamRule.MatchType.RESP_HEADER;
        } else if (matchTypeToStr(ReplacerParamRule.MatchType.RESP_HEADER_STR)
                .equals(selectedStr)) {
            return ReplacerParamRule.MatchType.RESP_HEADER_STR;
        } else if (matchTypeToStr(ReplacerParamRule.MatchType.RESP_BODY_STR).equals(selectedStr)) {
            return ReplacerParamRule.MatchType.RESP_BODY_STR;
        } else {
            return null;
        }
    }

    public void clear() {
        this.rule = null;
        this.setFieldValue(DESC_FIELD, "");
        this.setFieldValue(MATCH_STR_FIELD, "");
        this.setFieldValue(REPLACEMENT_FIELD, "");
        this.setFieldValue(ENABLE_FIELD, false);
    }
}
