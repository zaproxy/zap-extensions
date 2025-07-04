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
package org.zaproxy.addon.spider.automation;

import java.awt.Component;
import java.util.Arrays;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTextField;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.spider.SpiderParam;
import org.zaproxy.addon.spider.SpiderParam.HandleParametersOption;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class SpiderJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params",
        "spider.automation.dialog.tab.parse",
        "spider.automation.dialog.tab.adv"
    };

    private static final String TITLE = "spider.automation.dialog.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String CONTEXT_PARAM = "spider.automation.dialog.context";
    private static final String USER_PARAM = "automation.dialog.all.user";
    private static final String URL_PARAM = "spider.automation.dialog.url";
    private static final String MAX_DURATION_PARAM = "spider.automation.dialog.maxduration";
    private static final String MAX_DEPTH_PARAM = "spider.automation.dialog.maxdepth";
    private static final String MAX_CHILDREN_PARAM = "spider.automation.dialog.maxchildren";
    private static final String FIELD_ADVANCED = "spider.automation.dialog.advanced";

    private static final String ACCEPT_COOKIES_PARAM = "spider.automation.dialog.acceptcookies";
    private static final String HANDLE_ODATA_PARAM = "spider.automation.dialog.handleodata";
    private static final String HANDLE_PARAMS_PARAM = "spider.automation.dialog.handleparams";
    private static final String MAX_PARSE_PARAM = "spider.automation.dialog.maxparse";
    private static final String PARSE_COMMENTS_PARAM = "spider.automation.dialog.parsecomments";
    private static final String PARSE_GIT_PARAM = "spider.automation.dialog.parsegit";
    private static final String PARSE_DS_STORE_PARAM = "spider.automation.dialog.parsedsstore";
    private static final String PARSE_ROBOTS_PARAM = "spider.automation.dialog.parserobots";
    private static final String PARSE_SITEMAP_PARAM = "spider.automation.dialog.parsesitemap";
    private static final String PARSE_SVN_PARAM = "spider.automation.dialog.parsessvn";
    private static final String POST_FORM_PARAM = "spider.automation.dialog.postform";
    private static final String PROCESS_FORM_PARAM = "spider.automation.dialog.processform";
    private static final String SEND_REFERER_PARAM = "spider.automation.dialog.sendreferer";
    private static final String THREAD_COUNT_PARAM = "spider.automation.dialog.threadcount";
    private static final String USER_AGENT_PARAM = "spider.automation.dialog.useragent";
    private static final String LOGOUT_AVOIDANCE_PARAM = "spider.automation.dialog.logoutAvoidance";

    private SpiderJob job;
    private DefaultComboBoxModel<SpiderParam.HandleParametersOption> handleParamsModel;

    public SpiderJobDialog(SpiderJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 400),
                TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(0, CONTEXT_PARAM, contextNames, this.job.getParameters().getContext());

        List<String> users = job.getEnv().getAllUserNames();
        // Add blank option
        users.add(0, "");
        this.addComboField(0, USER_PARAM, users, this.job.getData().getParameters().getUser());

        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, URL_PARAM, null, true, false);
        Component urlField = this.getField(URL_PARAM);
        if (urlField instanceof JTextField) {
            ((JTextField) urlField).setText(this.job.getParameters().getUrl());
        }
        this.addNumberField(
                0,
                MAX_DURATION_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxDuration()));
        this.addNumberField(
                0,
                MAX_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxDepth()));
        this.addNumberField(
                0,
                MAX_CHILDREN_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxChildren()));
        this.addCheckBoxField(0, FIELD_ADVANCED, advOptionsSet());

        this.addFieldListener(FIELD_ADVANCED, e -> setAdvancedTabs(getBoolValue(FIELD_ADVANCED)));

        this.addPadding(0);

        this.addCheckBoxField(
                1,
                PARSE_COMMENTS_PARAM,
                JobUtils.unBox(this.job.getParameters().getParseComments()));
        this.addCheckBoxField(
                1, PARSE_GIT_PARAM, JobUtils.unBox(this.job.getParameters().getParseGit()));
        this.addCheckBoxField(
                1,
                PARSE_DS_STORE_PARAM,
                JobUtils.unBox(this.job.getParameters().getParseDsStore()));
        this.addCheckBoxField(
                1,
                PARSE_ROBOTS_PARAM,
                JobUtils.unBox(this.job.getParameters().getParseRobotsTxt()));
        this.addCheckBoxField(
                1,
                PARSE_SITEMAP_PARAM,
                JobUtils.unBox(this.job.getParameters().getParseSitemapXml()));
        this.addCheckBoxField(
                1, PARSE_SVN_PARAM, JobUtils.unBox(this.job.getParameters().getParseSVNEntries()));

        this.addPadding(1);

        this.addNumberField(
                2,
                MAX_PARSE_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxParseSizeBytes()));
        this.addNumberField(
                2,
                THREAD_COUNT_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getThreadCount()));

        handleParamsModel = new DefaultComboBoxModel<>();
        Arrays.stream(SpiderParam.HandleParametersOption.values())
                .forEach(v -> handleParamsModel.addElement(v));
        DefaultListCellRenderer renderer =
                new DefaultListCellRenderer() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public Component getListCellRendererComponent(
                            JList<?> list,
                            Object value,
                            int index,
                            boolean isSelected,
                            boolean cellHasFocus) {
                        JLabel label =
                                (JLabel)
                                        super.getListCellRendererComponent(
                                                list, value, index, isSelected, cellHasFocus);
                        if (value instanceof HandleParametersOption) {
                            // The name is i18n'ed
                            label.setText(((HandleParametersOption) value).getName());
                        }
                        return label;
                    }
                };

        if (this.job.getParameters().getHandleParameters() != null) {
            handleParamsModel.setSelectedItem(this.job.getParameters().getHandleParameters());
        }
        this.addComboField(2, HANDLE_PARAMS_PARAM, handleParamsModel);
        Component acField = this.getField(HANDLE_PARAMS_PARAM);
        if (acField instanceof JComboBox) {
            ((JComboBox<?>) acField).setRenderer(renderer);
        }

        this.addCheckBoxField(
                2,
                ACCEPT_COOKIES_PARAM,
                JobUtils.unBox(this.job.getParameters().getAcceptCookies()));
        this.addCheckBoxField(
                2,
                HANDLE_ODATA_PARAM,
                JobUtils.unBox(this.job.getParameters().getHandleODataParametersVisited()));

        this.addCheckBoxField(
                2, POST_FORM_PARAM, JobUtils.unBox(this.job.getParameters().getPostForm()));
        this.addCheckBoxField(
                2, PROCESS_FORM_PARAM, JobUtils.unBox(this.job.getParameters().getProcessForm()));
        this.addCheckBoxField(
                2,
                SEND_REFERER_PARAM,
                JobUtils.unBox(this.job.getParameters().getSendRefererHeader()));
        this.addCheckBoxField(
                2,
                LOGOUT_AVOIDANCE_PARAM,
                JobUtils.unBox(this.job.getParameters().getLogoutAvoidance()));
        this.addTextField(2, USER_AGENT_PARAM, this.job.getParameters().getUserAgent());

        this.addPadding(2);

        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
    }

    private boolean advOptionsSet() {
        SpiderJob.Parameters params = this.job.getParameters();
        return params.getAcceptCookies() != null
                || params.getHandleODataParametersVisited() != null
                || params.getMaxParseSizeBytes() != null
                || params.getParseComments() != null
                || params.getParseGit() != null
                || params.getParseDsStore() != null
                || params.getParseRobotsTxt() != null
                || params.getParseSitemapXml() != null
                || params.getParseSVNEntries() != null
                || params.getPostForm() != null
                || params.getProcessForm() != null
                || params.getSendRefererHeader() != null
                || params.getThreadCount() != null
                || params.getUserAgent() != null;
    }

    private void setAdvancedTabs(boolean visible) {
        // Show/hide all except from the first tab
        this.setTabsVisible(
                new String[] {
                    "spider.automation.dialog.tab.parse", "spider.automation.dialog.tab.adv"
                },
                visible);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setContext(this.getStringValue(CONTEXT_PARAM));
        this.job.getParameters().setUser(this.getStringValue(USER_PARAM));
        this.job.getParameters().setUrl(this.getStringValue(URL_PARAM));
        this.job.getParameters().setMaxDuration(this.getIntValue(MAX_DURATION_PARAM));
        this.job.getParameters().setMaxDepth(this.getIntValue(MAX_DEPTH_PARAM));
        this.job.getParameters().setMaxChildren(this.getIntValue(MAX_CHILDREN_PARAM));

        if (JobUtils.unBox(this.getBoolValue(FIELD_ADVANCED))) {
            this.job.getParameters().setAcceptCookies(this.getBoolValue(ACCEPT_COOKIES_PARAM));
            this.job
                    .getParameters()
                    .setHandleODataParametersVisited(this.getBoolValue(HANDLE_ODATA_PARAM));
            this.job.getParameters().setMaxParseSizeBytes(this.getIntValue(MAX_PARSE_PARAM));
            this.job.getParameters().setParseComments(this.getBoolValue(PARSE_COMMENTS_PARAM));
            this.job.getParameters().setParseGit(this.getBoolValue(PARSE_GIT_PARAM));
            this.job.getParameters().setParseDsStore(null);
            this.job.getParameters().setParseRobotsTxt(this.getBoolValue(PARSE_ROBOTS_PARAM));
            this.job.getParameters().setParseSitemapXml(this.getBoolValue(PARSE_SITEMAP_PARAM));
            this.job.getParameters().setParseSVNEntries(this.getBoolValue(PARSE_SVN_PARAM));
            this.job.getParameters().setPostForm(this.getBoolValue(POST_FORM_PARAM));
            this.job.getParameters().setProcessForm(this.getBoolValue(PROCESS_FORM_PARAM));
            this.job.getParameters().setSendRefererHeader(this.getBoolValue(SEND_REFERER_PARAM));
            this.job.getParameters().setUserAgent(this.getStringValue(USER_AGENT_PARAM));
            this.job.getParameters().setLogoutAvoidance(this.getBoolValue(LOGOUT_AVOIDANCE_PARAM));

            Object hpoObj = handleParamsModel.getSelectedItem();
            if (hpoObj instanceof SpiderParam.HandleParametersOption) {
                SpiderParam.HandleParametersOption hpo =
                        (SpiderParam.HandleParametersOption) hpoObj;
                this.job.getParameters().setHandleParameters(hpo);
            }

        } else {
            this.job.getParameters().setAcceptCookies(null);
            this.job.getParameters().setHandleODataParametersVisited(null);
            this.job.getParameters().setMaxParseSizeBytes(null);
            this.job.getParameters().setParseComments(null);
            this.job.getParameters().setParseGit(null);
            this.job.getParameters().setParseDsStore(null);
            this.job.getParameters().setParseRobotsTxt(null);
            this.job.getParameters().setParseSitemapXml(null);
            this.job.getParameters().setParseSVNEntries(null);
            this.job.getParameters().setPostForm(null);
            this.job.getParameters().setProcessForm(null);
            this.job.getParameters().setSendRefererHeader(null);
            this.job.getParameters().setUserAgent(null);
            this.job.getParameters().setHandleParameters(null);
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do TODO validate url - coping with envvars :O
        return null;
    }
}
