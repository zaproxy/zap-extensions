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
package org.zaproxy.addon.reports;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.WordUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ApiUtils;
import org.zaproxy.zap.utils.XMLStringUtil;

public class ReportApi extends ApiImplementor {
    private static final Logger LOG = LogManager.getLogger(ReportApi.class);
    private static final String DELIMITER_REGEX = "\\|";

    private static final String PREFIX = "reports";

    static final String ACTION_GENERATE = "generate";
    static final String VIEW_TEMPLATES = "templates";
    static final String VIEW_TEMPLATE_DETAILS = "templateDetails";

    static final String PARAM_CONTEXTS = "contexts";
    static final String PARAM_DESCRIPTION = "description";
    static final String PARAM_REPORT_DIRECTORY = "reportDir";
    static final String PARAM_REPORT_FILE_NAME = "reportFileName";
    static final String PARAM_SECTIONS = "sections";
    static final String PARAM_SITES = "sites";
    static final String PARAM_TEMPLATE = "template";
    static final String PARAM_THEME = "theme";
    static final String PARAM_TITLE = "title";
    static final String PARAM_DISPLAY = "display";
    static final String PARAM_INC_CONFIDENCES = "includedConfidences";
    static final String PARAM_INC_RISKS = "includedRisks";
    static final String PARAM_REPORT_FILE_NAME_PATTERN = "reportFileNamePattern";

    private final ExtensionReports extReports;

    /** Provided only for API client generator usage. */
    public ReportApi() {
        this(null);
    }

    public ReportApi(ExtensionReports extReports) {
        super();
        this.extReports = extReports;

        this.addApiAction(
                new ApiAction(
                        ACTION_GENERATE,
                        new String[] {
                            PARAM_TITLE, PARAM_TEMPLATE,
                        },
                        new String[] {
                            PARAM_THEME,
                            PARAM_DESCRIPTION,
                            PARAM_CONTEXTS,
                            PARAM_SITES,
                            PARAM_SECTIONS,
                            PARAM_INC_CONFIDENCES,
                            PARAM_INC_RISKS,
                            PARAM_REPORT_FILE_NAME,
                            PARAM_REPORT_FILE_NAME_PATTERN,
                            PARAM_REPORT_DIRECTORY,
                            PARAM_DISPLAY,
                        }));
        this.addApiView(new ApiView(VIEW_TEMPLATES));
        this.addApiView(new ApiView(VIEW_TEMPLATE_DETAILS, new String[] {PARAM_TEMPLATE}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOG.debug("Request for handleApiAction: {} (params: {})", name, params);
        switch (name) {
            case ACTION_GENERATE:
                ReportData reportData = new ReportData();

                reportData.setTitle(params.getString(PARAM_TITLE));

                Template template =
                        extReports.getTemplateByConfigName(params.getString(PARAM_TEMPLATE));
                if (template == null) {
                    throw new ApiException(
                            Type.DOES_NOT_EXIST,
                            Constant.messages.getString(
                                    "reports.api.error.templateDoesNotExist",
                                    params.getString(PARAM_TEMPLATE)));
                }

                List<String> themes = template.getThemes();
                if (isContainedParam(PARAM_THEME, params)) {
                    String theme = params.getString(PARAM_THEME);
                    if (!themes.contains(theme)) {
                        throw new ApiException(
                                Type.ILLEGAL_PARAMETER,
                                Constant.messages.getString(
                                        "reports.api.error.badTheme",
                                        theme,
                                        template.getConfigName()));
                    }
                    reportData.setTheme(theme);
                } else if (!themes.isEmpty()) {
                    reportData.setTheme(themes.get(0));
                }

                reportData.setDescription(params.optString(PARAM_DESCRIPTION, ""));

                if (isContainedParam(PARAM_CONTEXTS, params)) {
                    String[] contextNames = params.getString(PARAM_CONTEXTS).split(DELIMITER_REGEX);
                    List<Context> contextsList = new ArrayList<>();
                    for (String contextName : contextNames) {
                        contextsList.add(ApiUtils.getContextByName(contextName));
                    }
                    reportData.setContexts(contextsList);
                } else {
                    reportData.setContexts(Collections.emptyList());
                }

                List<String> sitesList = new ArrayList<>();
                if (isContainedParam(PARAM_SITES, params)) {
                    sitesList.addAll(
                            Arrays.asList(params.getString(PARAM_SITES).split(DELIMITER_REGEX)));
                    reportData.setSites(sitesList);
                } else {
                    reportData.setSites(ExtensionReports.getSites());
                }

                if (isContainedParam(PARAM_SECTIONS, params)) {
                    List<String> inputSections =
                            Arrays.stream(params.getString(PARAM_SECTIONS).split(DELIMITER_REGEX))
                                    .map(String::trim)
                                    .collect(Collectors.toList());
                    List<String> invalidSections =
                            inputSections.stream()
                                    .filter(s -> !template.getSections().contains(s))
                                    .collect(Collectors.toList());
                    if (!invalidSections.isEmpty()) {
                        throw new ApiException(
                                Type.ILLEGAL_PARAMETER,
                                Constant.messages.getString(
                                        "reports.api.error.badSections",
                                        invalidSections,
                                        template.getConfigName()));
                    }
                    reportData.setSections(inputSections);
                } else {
                    reportData.setSections(template.getSections());
                }

                if (isContainedParam(PARAM_INC_CONFIDENCES, params)) {
                    reportData.setIncludeAllConfidences(false);
                    String[] confidences =
                            params.getString(PARAM_INC_CONFIDENCES).split(DELIMITER_REGEX);
                    for (String confidence : confidences) {
                        confidence =
                                WordUtils.capitalize(confidence.trim().toLowerCase(Locale.ROOT));
                        int confidenceIndex = ArrayUtils.indexOf(Alert.MSG_CONFIDENCE, confidence);
                        if (confidenceIndex == -1) {
                            throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_INC_CONFIDENCES);
                        }
                        reportData.setIncludeConfidence(confidenceIndex, true);
                    }
                } else {
                    reportData.setIncludeAllConfidences(true);
                }

                if (isContainedParam(PARAM_INC_RISKS, params)) {
                    reportData.setIncludeAllRisks(false);
                    String[] risks = params.getString(PARAM_INC_RISKS).split(DELIMITER_REGEX);
                    for (String risk : risks) {
                        risk = WordUtils.capitalize(risk.trim().toLowerCase(Locale.ROOT));
                        int riskIndex = ArrayUtils.indexOf(Alert.MSG_RISK, risk);
                        if (riskIndex == -1) {
                            throw new ApiException(Type.ILLEGAL_PARAMETER, PARAM_INC_RISKS);
                        }
                        reportData.setIncludeRisk(riskIndex, true);
                    }
                } else {
                    reportData.setIncludeAllRisks(true);
                }

                reportData.setAlertTreeRootNode(extReports.getFilteredAlertTree(reportData));

                String paramReportDir = System.getProperty("user.home");
                if (isContainedParam(PARAM_REPORT_DIRECTORY, params)) {
                    paramReportDir = params.getString(PARAM_REPORT_DIRECTORY);
                    if (!Files.isWritable(Paths.get(paramReportDir))) {
                        String response =
                                Constant.messages.getString(
                                        "reports.dialog.error.dirperms", paramReportDir);
                        throw new ApiException(Type.ILLEGAL_PARAMETER, response);
                    }
                }

                String reportFileName =
                        isContainedParam(PARAM_REPORT_FILE_NAME, params)
                                ? params.getString(PARAM_REPORT_FILE_NAME)
                                : ExtensionReports.getNameFromPattern(
                                        isContainedParam(PARAM_REPORT_FILE_NAME_PATTERN, params)
                                                ? params.getString(PARAM_REPORT_FILE_NAME_PATTERN)
                                                : ReportParam.DEFAULT_NAME_PATTERN,
                                        (sitesList.size() > 0 ? sitesList.get(0) : ""));
                if (!reportFileName.endsWith(template.getExtension())) {
                    reportFileName += '.' + template.getExtension();
                }
                String reportFilePath = Paths.get(paramReportDir, reportFileName).toString();

                boolean display = params.optBoolean(PARAM_DISPLAY, false);

                try {
                    extReports.generateReport(reportData, template, reportFilePath, display);
                } catch (Exception e) {
                    throw new ApiException(Type.INTERNAL_ERROR, e);
                }
                return new ApiResponseElement(name, reportFilePath);
            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        LOG.debug("Request for handleApiView: {} (params: {})", name, params);
        switch (name) {
            case VIEW_TEMPLATES:
                ApiResponseList resultList = new ApiResponseList(name);
                extReports
                        .getTemplates()
                        .forEach(
                                t ->
                                        resultList.addItem(
                                                new ApiResponseElement(
                                                        "template", t.getConfigName())));
                return resultList;
            case VIEW_TEMPLATE_DETAILS:
                Template template =
                        extReports.getTemplateByConfigName(params.getString(PARAM_TEMPLATE));
                if (template == null) {
                    throw new ApiException(
                            Type.DOES_NOT_EXIST,
                            Constant.messages.getString(
                                    "reports.api.error.templateDoesNotExist",
                                    params.getString(PARAM_TEMPLATE)));
                }
                ApiResponseSet<Object> resultSet =
                        new CustomApiResponseSet<>(name, new HashMap<>());
                resultSet.put("name", template.getDisplayName());
                resultSet.put("format", template.getFormat());
                JSONArray sections = new JSONArray();
                sections.addAll(template.getSections());
                resultSet.put("sections", sections);
                JSONArray themes = new JSONArray();
                themes.addAll(template.getThemes());
                resultSet.put("themes", themes);
                return resultSet;
            default:
                throw new ApiException(Type.BAD_VIEW);
        }
    }

    static class CustomApiResponseSet<T> extends ApiResponseSet<T> {
        public CustomApiResponseSet(String name, Map<String, T> values) {
            super(name, values);
        }

        @Override
        public void toXML(Document doc, Element parent) {
            parent.setAttribute("type", "set");

            for (Map.Entry<String, T> val : getValues().entrySet()) {
                Element el = doc.createElement(val.getKey());
                if ("themes".equals(val.getKey()) || "sections".equals(val.getKey())) {
                    el.setAttribute("type", "list");
                    JSONArray array = (JSONArray) val.getValue();
                    for (int i = 0; i < array.size(); ++i) {
                        Element elChild =
                                doc.createElement(
                                        val.getKey().substring(0, val.getKey().length() - 1));
                        elChild.appendChild(
                                doc.createTextNode(
                                        XMLStringUtil.escapeControlChrs(array.getString(i))));
                        el.appendChild(elChild);
                    }
                } else {
                    String textValue = val.getValue() == null ? "" : val.getValue().toString();
                    Text text = doc.createTextNode(XMLStringUtil.escapeControlChrs(textValue));
                    el.appendChild(text);
                }
                parent.appendChild(el);
            }
        };
    }

    private static boolean isContainedParam(String paramName, JSONObject params) {
        return params.containsKey(paramName) && !params.getString(paramName).isEmpty();
    }
}
