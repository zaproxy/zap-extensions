/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.bugtracker;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SortOrder;
import org.apache.log4j.Logger;
import org.kohsuke.github.GHIssueBuilder;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.HttpException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.AbstractMultipleOptionsTablePanel;

public class BugTrackerGithub extends BugTracker {

    private String NAME = "Github";
    private String FIELD_REPO = "bugtracker.trackers.github.issue.repo";
    private String FIELD_TITLE = "bugtracker.trackers.github.issue.title";
    private String FIELD_BODY = "bugtracker.trackers.github.issue.body";
    private String FIELD_LABELS = "bugtracker.trackers.github.issue.labels";
    private String FIELD_ASSIGNEE_MANUAL = "bugtracker.trackers.github.issue.assignee.manual";
    private String FIELD_ASSIGNEE_LIST = "bugtracker.trackers.github.issue.assignee.list";
    private String FIELD_USERNAME = "bugtracker.trackers.github.issue.username";
    private String FIELD_PASSWORD = "bugtracker.trackers.github.issue.password";
    private String FIELD_GITHUB_CONFIG = "bugtracker.trackers.github.issue.config";
    private String titleIssue = null;
    private String bodyIssue = null;
    private String labelsIssue = null;
    private JPanel githubPanel = null;
    private BugTrackerGithubTableModel githubModel = null;
    private RaiseSemiAutoIssueDialog dialog = null;

    private static final Logger log = Logger.getLogger(BugTrackerGithub.class);

    public BugTrackerGithub() {
        initializeConfigTable();
    }

    @Override
    public void setDetails(Set<Alert> alerts) {
        setTitle(alerts);
        setBody(alerts);
        setLabels(alerts);
    }

    @Override
    public void setDialog(RaiseSemiAutoIssueDialog dialog) {
        this.dialog = dialog;
    }

    public void initializeConfigTable() {
        githubPanel = new BugTrackerGithubMultipleOptionsPanel(getGithubModel());
    }

    @Override
    public JPanel getConfigPanel() {
        return githubPanel;
    }

    @Override
    public void createDialogs() {
        List<BugTrackerGithubConfigParams> configs = getOptions().getConfigs();
        Set<String> collaborators = new HashSet<String>();
        List<String> configNames = new ArrayList<String>();
        for (BugTrackerGithubConfigParams config : configs) {
            configNames.add(config.getName());
        }
        dialog.setXWeights(0.1D, 0.9D);
        dialog.addComboField(FIELD_GITHUB_CONFIG, configNames, "");
        dialog.addTextField(FIELD_REPO, "");
        dialog.addTextField(FIELD_TITLE, getTitle());
        dialog.addMultilineField(FIELD_BODY, getBody());
        dialog.addTextField(FIELD_LABELS, getLabels());
        dialog.addTextField(FIELD_ASSIGNEE_MANUAL, "");
        dialog.addComboField(FIELD_ASSIGNEE_LIST, new ArrayList<String>(), "");
        dialog.addTextField(FIELD_USERNAME, "");
        dialog.addTextField(FIELD_PASSWORD, "");
        updateAssigneeList();
        dialog.addFieldListener(
                FIELD_GITHUB_CONFIG,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        updateAssigneeList();
                    }
                });
    }

    public void updateAssigneeList() {
        try {
            String currentItem = dialog.getStringValue(FIELD_GITHUB_CONFIG);
            Set<String> collaborators = new HashSet<String>();
            List<BugTrackerGithubConfigParams> configs = getOptions().getConfigs();
            for (BugTrackerGithubConfigParams config : configs) {
                if (config.getName().equals(currentItem)) {
                    String repoFormatted = config.getRepoUrl();
                    if (repoFormatted.contains("https://github.com")) {
                        repoFormatted = repoFormatted.split("https://github.com/")[1];
                    } else if (repoFormatted.contains("https://www.github.com")) {
                        repoFormatted = repoFormatted.split("https://www.github.com/")[1];
                    }
                    collaborators =
                            getCollaborators(config.getName(), config.getPassword(), repoFormatted);
                    if (collaborators != null && collaborators.size() > 0) {
                        List<String> assignees = new ArrayList<String>(collaborators);
                        dialog.setComboFields(FIELD_ASSIGNEE_LIST, assignees, "");
                    } else {
                        List<String> assignees = new ArrayList<String>();
                        dialog.setComboFields(FIELD_ASSIGNEE_LIST, assignees, "");
                    }
                }
            }
        } catch (IOException e) {
            String response = e.toString();
            if (response.contains("missing_field")) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "bugtracker.trackers.github.issue.msg.missing"));
            } else if (response.contains("invalid")) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "bugtracker.trackers.github.issue.msg.param"));
            }
        }
    }

    public void setTitle(Set<Alert> alerts) {
        StringBuilder title = new StringBuilder("");
        for (Alert alert : alerts) {
            if (alert.getName().length() > 0) {
                title.append(alert.getName().toString() + ", ");
            }
        }
        title.replace(title.length() - 2, title.length() - 1, "");
        titleIssue = title.toString();
    }

    public void setBody(Set<Alert> alerts) {
        StringBuilder body = new StringBuilder("");
        for (Alert alert : alerts) {

            if (alert.getName().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.alert")
                                + alert.getName().toString()
                                + "\n\n");
            }
            if (alert.getUri().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.url")
                                + alert.getUri().toString()
                                + "\n\n");
            }
            if (alert.getDescription().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.desc")
                                + alert.getDescription().toString()
                                + "\n\n");
            }
            if (alert.getOtherInfo().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.otherinfo")
                                + alert.getOtherInfo().toString()
                                + "\n\n");
            }
            if (alert.getSolution().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.solution")
                                + alert.getSolution().toString()
                                + "\n\n");
            }
            if (alert.getReference().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.reference")
                                + alert.getReference().toString()
                                + "\n\n");
            }
            if (alert.getParam().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.parameter")
                                + alert.getParam().toString()
                                + "\n\n");
            }
            if (alert.getAttack().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.attack")
                                + alert.getAttack().toString()
                                + "\n\n");
            }
            if (alert.getEvidence().length() > 0) {
                body.append(
                        Constant.messages.getString("bugtracker.msg.evidence")
                                + alert.getEvidence().toString()
                                + "\n\n\n\n");
            }
        }
        bodyIssue = body.toString();
    }

    public void setLabels(Set<Alert> alerts) {
        StringBuilder labels = new StringBuilder("");
        for (Alert alert : alerts) {

            if (alert.getRisk() >= 0) {
                labels.append(
                        Constant.messages.getString("bugtracker.msg.risk")
                                + Alert.MSG_RISK[alert.getRisk()]
                                + ", ");
            }
            if (alert.getConfidence() >= 0) {
                labels.append(
                        Constant.messages.getString("bugtracker.msg.conf")
                                + Alert.MSG_CONFIDENCE[alert.getConfidence()]
                                + ", ");
            }
            if (alert.getCweId() >= 0) {
                labels.append(
                        Constant.messages.getString("bugtracker.msg.cwe")
                                + alert.getCweId()
                                + ", ");
            }
            if (alert.getWascId() >= 0) {
                labels.append(
                        Constant.messages.getString("bugtracker.msg.wasc")
                                + alert.getWascId()
                                + ", ");
            }
        }
        labelsIssue = labels.toString();
    }

    public String getTitle() {
        return this.titleIssue;
    }

    public String getBody() {
        return this.bodyIssue;
    }

    public String getLabels() {
        return this.labelsIssue;
    }

    public Set<String> getCollaborators(String username, String password, String repo)
            throws IOException {
        GitHub github = GitHub.connectUsingPassword(username, password);
        Set<String> collaborators = null;
        try {
            GHRepository repository = github.getRepository(repo);
            collaborators = repository.getCollaboratorNames();
        } catch (ArrayIndexOutOfBoundsException e) {
            log.debug(Constant.messages.getString("bugtracker.trackers.github.issue.msg.repo"));
        } catch (HttpException e) {
            String response = e.toString();
            log.debug(response);
            if (response.contains("Unauthorized")) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "bugtracker.trackers.github.issue.msg.auth"));
            } else {
                View.getSingleton().showWarningDialog(response);
            }
        }
        return collaborators;
    }

    public String raiseOnTracker(
            String repo,
            String title,
            String body,
            String labels,
            String assignee,
            String username,
            String password)
            throws IOException {
        GitHub github = GitHub.connectUsingPassword(username, password);
        try {
            GHRepository repository = github.getRepository(repo);
            GHIssueBuilder issue = repository.createIssue(title);
            issue.body(body);
            issue.assignee(assignee);
            String[] labelArray = labels.split(",\\s");
            for (int i = 0; i < labelArray.length; i++) {
                issue.label(labelArray[i]);
            }
            issue.create();
            return null;
        } catch (ArrayIndexOutOfBoundsException e) {
            log.debug(e.toString());
            return Constant.messages.getString("bugtracker.trackers.github.issue.msg.repo");
        } catch (HttpException e) {
            String response = e.toString();
            log.debug(response);
            if (response.contains("Unauthorized")) {
                return Constant.messages.getString("bugtracker.trackers.github.issue.msg.auth");
            } else {
                return response;
            }
        }
    }

    public String raise() {
        String repo, title, body, labels, assignee, username, password;
        repo = "";
        title = getTitle();
        body = getBody();
        labels = getLabels();
        assignee = "";
        username = "";
        password = "";
        try {
            String response =
                    raiseOnTracker(repo, title, body, labels, assignee, username, password);
            return response;
        } catch (FileNotFoundException e) {
            log.debug(e.toString());
            return Constant.messages.getString("bugtracker.trackers.github.issue.msg.repo");
        } catch (IOException e) {
            String response = e.toString();
            log.debug(response);
            if (response.contains("missing_field")) {
                return Constant.messages.getString("bugtracker.trackers.github.issue.msg.missing");
            } else if (response.contains("invalid")) {
                return Constant.messages.getString("bugtracker.trackers.github.issue.msg.param");
            } else {
                return response;
            }
        }
    }

    @Override
    public String raise(RaiseSemiAutoIssueDialog dialog) {
        String repo, title, body, labels, assignee, username, password, configGithub;
        repo = dialog.getStringValue(FIELD_REPO);
        title = dialog.getStringValue(FIELD_TITLE);
        body = dialog.getStringValue(FIELD_BODY);
        labels = dialog.getStringValue(FIELD_LABELS);
        assignee = dialog.getStringValue(FIELD_ASSIGNEE_MANUAL);
        username = dialog.getStringValue(FIELD_USERNAME);
        password = dialog.getStringValue(FIELD_PASSWORD);
        configGithub = dialog.getStringValue(FIELD_GITHUB_CONFIG);
        if (repo.equals("") || username.equals("") || password.equals("")) {
            List<BugTrackerGithubConfigParams> configs = getOptions().getConfigs();
            for (BugTrackerGithubConfigParams config : configs) {
                if (config.getName().equals(configGithub)) {
                    username = config.getName();
                    password = config.getPassword();
                }
            }
        }
        if (repo.equals("")) {
            List<BugTrackerGithubConfigParams> configs = getOptions().getConfigs();
            for (BugTrackerGithubConfigParams config : configs) {
                if (config.getName().equals(configGithub)) {
                    repo = config.getRepoUrl();
                    if (repo.contains("https://github.com/")) {
                        repo = repo.split("https://github.com/")[1];
                    } else if (repo.contains("https://www.github.com/")) {
                        repo = repo.split("https://www.github.com/")[1];
                    }
                }
            }
        }
        if (assignee.equals("")) {
            assignee = dialog.getStringValue(FIELD_ASSIGNEE_LIST);
        }
        try {
            String response =
                    raiseOnTracker(repo, title, body, labels, assignee, username, password);
            return response;
        } catch (FileNotFoundException e) {
            log.debug(e.toString());
            return Constant.messages.getString("bugtracker.trackers.github.issue.msg.repo");
        } catch (IOException e) {
            String response = e.toString();
            log.debug(response);
            if (response.contains("missing_field")) {
                return Constant.messages.getString("bugtracker.trackers.github.issue.msg.missing");
            } else if (response.contains("invalid")) {
                return Constant.messages.getString("bugtracker.trackers.github.issue.msg.param");
            } else {
                return response;
            }
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getId() {
        return NAME.toLowerCase();
    }

    /**
     * This method initializes authModel
     *
     * @return org.parosproxy.paros.view.OptionsAuthenticationTableModel
     */
    private BugTrackerGithubTableModel getGithubModel() {
        if (githubModel == null) {
            githubModel = new BugTrackerGithubTableModel();
        }
        return githubModel;
    }

    private BugTrackerGithubParam options;

    public BugTrackerGithubParam getOptions() {
        if (options == null) {
            options = new BugTrackerGithubParam();
        }
        return options;
    }

    public static class BugTrackerGithubMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<BugTrackerGithubConfigParams> {

        private static final long serialVersionUID = -115340627058929308L;

        private static final String REMOVE_DIALOG_TITLE =
                Constant.messages.getString(
                        "bugtracker.trackers.github.dialog.config.remove.title");
        private static final String REMOVE_DIALOG_TEXT =
                Constant.messages.getString("bugtracker.trackers.github.dialog.config.remove.text");

        private static final String REMOVE_DIALOG_CONFIRM_BUTTON_LABEL =
                Constant.messages.getString(
                        "bugtracker.trackers.github.dialog.config.remove.button.confirm");
        private static final String REMOVE_DIALOG_CANCEL_BUTTON_LABEL =
                Constant.messages.getString(
                        "bugtracker.trackers.github.dialog.config.remove.button.cancel");

        private static final String REMOVE_DIALOG_CHECKBOX_LABEL =
                Constant.messages.getString(
                        "bugtracker.trackers.github.dialog.config.remove.checkbox.label");

        private DialogAddGithubConfig addDialog = null;
        private DialogModifyGithubConfig modifyDialog = null;

        private BugTrackerGithubTableModel model;

        public BugTrackerGithubMultipleOptionsPanel(BugTrackerGithubTableModel model) {
            super(model);

            this.model = model;

            getTable().getColumnExt(0).setPreferredWidth(20);
            getTable().setSortOrder(1, SortOrder.ASCENDING);
        }

        @Override
        public BugTrackerGithubConfigParams showAddDialogue() {
            if (addDialog == null) {
                addDialog = new DialogAddGithubConfig(View.getSingleton().getOptionsDialog(null));
                addDialog.pack();
            }
            addDialog.setConfigs(model.getElements());
            addDialog.setVisible(true);

            BugTrackerGithubConfigParams config = addDialog.getConfig();
            addDialog.clear();

            return config;
        }

        @Override
        public BugTrackerGithubConfigParams showModifyDialogue(BugTrackerGithubConfigParams e) {
            if (modifyDialog == null) {
                modifyDialog =
                        new DialogModifyGithubConfig(View.getSingleton().getOptionsDialog(null));
                modifyDialog.pack();
            }
            modifyDialog.setConfigs(model.getElements());
            modifyDialog.setConfig(e);
            modifyDialog.setVisible(true);

            BugTrackerGithubConfigParams config = modifyDialog.getConfig();
            modifyDialog.clear();

            if (!config.equals(e)) {
                return config;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(BugTrackerGithubConfigParams e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(REMOVE_DIALOG_CHECKBOX_LABEL);
            Object[] messages = {REMOVE_DIALOG_TEXT, " ", removeWithoutConfirmationCheckBox};
            int option =
                    JOptionPane.showOptionDialog(
                            View.getSingleton().getMainFrame(),
                            messages,
                            REMOVE_DIALOG_TITLE,
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                REMOVE_DIALOG_CONFIRM_BUTTON_LABEL,
                                REMOVE_DIALOG_CANCEL_BUTTON_LABEL
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }

    private BugTrackerGithubOptionsPanel optionsPanel;

    @Override
    public BugTrackerGithubOptionsPanel getOptionsPanel() {
        if (optionsPanel == null) {
            optionsPanel = new BugTrackerGithubOptionsPanel();
        }
        return optionsPanel;
    }
}
