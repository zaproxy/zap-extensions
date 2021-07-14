/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan.ui;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.Border;
import javax.swing.border.EtchedBorder;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.ManualAuthenticationMethodType.ManualAuthenticationMethod;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus;
import org.zaproxy.zap.extension.users.ContextUsersPanel;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ContextIncludePanel;

public class AuthenticationConfigurationChecklistPanel extends JPanel {

    private static final long serialVersionUID = 8228766560419086082L;

    private static final Logger logger =
            Logger.getLogger(AuthenticationConfigurationChecklistPanel.class);

    /**
     * Constant indicating the authentication <strong>configuration</strong> status. This can be one
     * of {@code GOOD, BAD, MINIMAL, NOT_VALIDATED_YET}.
     *
     * <p>This should be differentiated from {@link AuthenticationStatus} which indicates the
     * <strong>authentication</strong> status, based on the presence of logged in/out indicator in
     * the response message.
     */
    public enum ConfigurationStatus {
        GOOD,
        BAD,
        MINIMAL,
        NOT_VALIDATED_YET;
    }

    /**
     * Matching {@code Icon} for {@code ConfigurationStatus.GOOD}
     *
     * <p>Eagerly loaded.
     *
     * @see ConfigurationStatus
     */
    private static final Icon GOOD_CONFIGURATION_ICON;

    /**
     * Matching {@code Icon} for {@code ConfigurationStatus.BAD}
     *
     * <p>Eagerly loaded.
     *
     * @see ConfigurationStatus
     */
    private static final Icon BAD_CONFIGURATION_ICON;
    /**
     * Matching {@code Icon} for {@code ConfigurationStatus.NOT_VALIDATED_YET}
     *
     * <p>Eagerly loaded.
     *
     * @see ConfigurationStatus
     */
    private static final Icon NOT_VALIDATED_YET_ICON;

    /**
     * Matching {@code Icon} for {@code ConfigurationStatus.MINIMAL}
     *
     * <p>Eagerly loaded.
     *
     * @see ConfigurationStatus
     */
    private static final Icon MINIMAL_CONFIGURATION_ICON;

    private final AuthenticationHelperDialog helperDialog;

    private final JLabel labelHint;
    private final JLabel labelChecklistItemTarget;
    private final JLabel labelChecklistItemContext;
    private final JLabel labelChecklistItemUser;
    private final JLabel labelChecklistItemAuthenticationMethod;
    private final JLabel labelChecklistItemIndicator;

    private JButton btnSettings;

    private ConfigurationStatus overallConfigurationStatus;

    private final Map<JLabel, ConfigurationStatus> checklistStatusMap;

    static {
        GOOD_CONFIGURATION_ICON =
                new ImageIcon(
                        AuthenticationConfigurationChecklistPanel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/tick-circle.png"));
        NOT_VALIDATED_YET_ICON =
                new ImageIcon(
                        AuthenticationConfigurationChecklistPanel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/question-white.png"));
        BAD_CONFIGURATION_ICON =
                new ImageIcon(
                        AuthenticationConfigurationChecklistPanel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/cross-circle.png"));
        MINIMAL_CONFIGURATION_ICON =
                new ImageIcon(
                        AuthenticationConfigurationChecklistPanel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/exclamation-circle.png"));
    }

    public AuthenticationConfigurationChecklistPanel(AuthenticationHelperDialog helperDialog) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        this.helperDialog = helperDialog;

        labelHint = new JLabel();
        labelChecklistItemTarget =
                new JLabel(
                        Constant.messages.getString("authenticationhelper.checklist.label.target"),
                        NOT_VALIDATED_YET_ICON,
                        JLabel.LEFT);
        labelChecklistItemContext =
                new JLabel(
                        Constant.messages.getString("authenticationhelper.checklist.label.context"),
                        NOT_VALIDATED_YET_ICON,
                        JLabel.LEFT);
        labelChecklistItemUser =
                new JLabel(
                        Constant.messages.getString("authenticationhelper.checklist.label.user"),
                        NOT_VALIDATED_YET_ICON,
                        JLabel.LEFT);
        labelChecklistItemAuthenticationMethod =
                new JLabel(
                        Constant.messages.getString(
                                "authenticationhelper.checklist.label.authentication"),
                        NOT_VALIDATED_YET_ICON,
                        JLabel.LEFT);
        labelChecklistItemIndicator =
                new JLabel(
                        Constant.messages.getString(
                                "authenticationhelper.checklist.label.loggedInOutIndicator"),
                        NOT_VALIDATED_YET_ICON,
                        JLabel.LEFT);

        checklistStatusMap = new HashMap<>();
        checklistStatusMap.put(labelChecklistItemTarget, ConfigurationStatus.NOT_VALIDATED_YET);
        checklistStatusMap.put(labelChecklistItemContext, ConfigurationStatus.NOT_VALIDATED_YET);
        checklistStatusMap.put(
                labelChecklistItemAuthenticationMethod, ConfigurationStatus.NOT_VALIDATED_YET);
        checklistStatusMap.put(labelChecklistItemUser, ConfigurationStatus.NOT_VALIDATED_YET);
        checklistStatusMap.put(labelChecklistItemIndicator, ConfigurationStatus.NOT_VALIDATED_YET);

        JPanel hintPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel targetStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel contextStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel userStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel authenticationMethodStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel loggedInOutIndicatorStatusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        Border emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
        Border etchedBorder = BorderFactory.createEtchedBorder(EtchedBorder.RAISED);
        hintPanel.setBorder(BorderFactory.createCompoundBorder(emptyBorder, etchedBorder));
        hintPanel.add(getBtnSettings());
        hintPanel.add(labelHint);

        targetStatusPanel.add(labelChecklistItemTarget);
        contextStatusPanel.add(labelChecklistItemContext);
        authenticationMethodStatusPanel.add(labelChecklistItemAuthenticationMethod);
        userStatusPanel.add(labelChecklistItemUser);
        loggedInOutIndicatorStatusPanel.add(labelChecklistItemIndicator);

        add(hintPanel);
        add(targetStatusPanel);
        add(contextStatusPanel);
        add(authenticationMethodStatusPanel);
        add(userStatusPanel);
        add(loggedInOutIndicatorStatusPanel);

        Border outterBorder = BorderFactory.createEmptyBorder(10, 5, 5, 5);
        Border innerBorder = BorderFactory.createEtchedBorder(EtchedBorder.LOWERED);
        setBorder(BorderFactory.createCompoundBorder(outterBorder, innerBorder));
    }

    public void runCheck() {
        overallConfigurationStatus = ConfigurationStatus.NOT_VALIDATED_YET;

        checkTargetAndUpdateMap();
        checkContextAndUpdateMap();
        checkAuthenticationMethodAndUpdateMap();
        checkUserAndUpdateMap();
        checkIndicatorAndUpdateMap();

        determineOverallStatusAndSetupHintPanel();

        updateStatusIconForChecklistItems();
    }

    /**
     * Checks if the user has provided valid {@link Target}. <br>
     * if {@code true} {@code (labelChecklistItemTarget, ConfigurationStatus.GOOD)} is put into
     * {@code checklistStatusMap}. <br>
     * if {@code false} {@code (labelChecklistItemTarget, ConfigurationStatus.BAD)} is put into
     * {@code checklistStatusMap}
     */
    private void checkTargetAndUpdateMap() {
        boolean isBadConfiguration =
                helperDialog.getTarget() == null || helperDialog.getTarget().getStartNode() == null;
        resolveStausAndUpdateMap(labelChecklistItemTarget, isBadConfiguration);
    }

    /**
     * Checks if a {@link Context} is defined for the selected {@link Target}. <br>
     * if {@code true} {@code (labelChecklistItemContext, ConfigurationStatus.GOOD)} is put into
     * {@code checklistStatusMap}. <br>
     * if {@code false} {@code (labelChecklistItemContext, ConfigurationStatus.BAD)} is put into
     * {@code checklistStatusMap}
     */
    private void checkContextAndUpdateMap() {
        boolean isBadConfiguration =
                !checklistStatusMap.get(labelChecklistItemTarget).equals(ConfigurationStatus.GOOD)
                        || getSelectedContext() == null;
        resolveStausAndUpdateMap(labelChecklistItemContext, isBadConfiguration);
    }

    /**
     * Checks if {@link AuthenticationMethod} is configured correctly for the selected {@link
     * Context}. <br>
     * if {@code true} {@code (labelChecklistItemAuthenticationMethod, ConfigurationStatus.GOOD)} is
     * put into {@code checklistStatusMap}. <br>
     * if {@code false} {@code (labelChecklistItemAuthenticationMethod, ConfigurationStatus.BAD)} is
     * put into {@code checklistStatusMap}
     */
    private void checkAuthenticationMethodAndUpdateMap() {
        AuthenticationMethod authenticationMethod = getConfiguredAuthenticationMethod();
        boolean isBadConfiguration =
                !checklistStatusMap.get(labelChecklistItemTarget).equals(ConfigurationStatus.GOOD)
                        || !checklistStatusMap
                                .get(labelChecklistItemContext)
                                .equals(ConfigurationStatus.GOOD)
                        || authenticationMethod == null
                        || !authenticationMethod.isConfigured()
                        || authenticationMethod instanceof ManualAuthenticationMethod;
        resolveStausAndUpdateMap(labelChecklistItemAuthenticationMethod, isBadConfiguration);
    }

    /**
     * Checks if a {@link User} is configured correctly for the selected {@link Context}. <br>
     * if {@code true} {@code (labelChecklistItemUser, ConfigurationStatus.GOOD)} is put into {@code
     * checklistStatusMap}. <br>
     * if {@code false} {@code (labelChecklistItemUser, ConfigurationStatus.BAD)} is put into {@code
     * checklistStatusMap}
     */
    private void checkUserAndUpdateMap() {
        User selectedUser = getSelectedUser();
        boolean isBadConfiguration =
                !checklistStatusMap.get(labelChecklistItemTarget).equals(ConfigurationStatus.GOOD)
                        || !checklistStatusMap
                                .get(labelChecklistItemContext)
                                .equals(ConfigurationStatus.GOOD)
                        || !checklistStatusMap
                                .get(labelChecklistItemAuthenticationMethod)
                                .equals(ConfigurationStatus.GOOD)
                        || selectedUser == null
                        || !selectedUser.getAuthenticationCredentials().isConfigured();
        resolveStausAndUpdateMap(labelChecklistItemUser, isBadConfiguration);
    }

    /**
     * Checks if {@code loggedInIndicator} and {@code loggedOutIndicator} are defined for the
     * selected {@link Context}.<br>
     * if both are defined {@code (labelChecklistItemIndicator, ConfigurationStatus.GOOD)} is put
     * into {@code checklistStatusMap}. <br>
     * if only one of them is defined {@code (labelChecklistItemIndicator,
     * ConfigurationStatus.MINIMAL)} is put into {@code checklistStatusMap} if none is defined
     * {@code (labelChecklistItemIndicator, ConfigurationStatus.BAD)} is
     */
    private void checkIndicatorAndUpdateMap() throws IllegalArgumentException {
        ConfigurationStatus status;
        boolean isBadPreCondition =
                !checklistStatusMap.get(labelChecklistItemTarget).equals(ConfigurationStatus.GOOD)
                        || !checklistStatusMap
                                .get(labelChecklistItemContext)
                                .equals(ConfigurationStatus.GOOD);

        if (isBadPreCondition) {
            status = ConfigurationStatus.BAD;
        } else {
            boolean inDefined =
                    indicatorDefined(
                            getConfiguredAuthenticationMethod().getLoggedInIndicatorPattern());
            boolean outDefined =
                    indicatorDefined(
                            getConfiguredAuthenticationMethod().getLoggedOutIndicatorPattern());
            if (inDefined && outDefined) {
                status = ConfigurationStatus.GOOD;
            } else if (inDefined || outDefined) {
                status = ConfigurationStatus.MINIMAL;
            } else {
                status = ConfigurationStatus.BAD;
            }
        }
        checklistStatusMap.put(labelChecklistItemIndicator, status);
    }

    private void determineOverallStatusAndSetupHintPanel() {
        if (!checklistStatusMap.get(labelChecklistItemTarget).equals(ConfigurationStatus.GOOD)) {
            overallConfigurationStatus = ConfigurationStatus.BAD;
            setHintPanelToMatchBadTarget();
            return;
        }

        if (!checklistStatusMap.get(labelChecklistItemContext).equals(ConfigurationStatus.GOOD)) {
            overallConfigurationStatus = ConfigurationStatus.BAD;
            setHintPanelToMatchBadContext();
            return;
        }

        if (!checklistStatusMap
                .get(labelChecklistItemAuthenticationMethod)
                .equals(ConfigurationStatus.GOOD)) {
            overallConfigurationStatus = ConfigurationStatus.BAD;
            setHintPanelToMatchBadAuthenticationMethod();
            return;
        }

        if (!checklistStatusMap.get(labelChecklistItemUser).equals(ConfigurationStatus.GOOD)) {
            overallConfigurationStatus = ConfigurationStatus.BAD;
            setHintPanelToMatchBadUser();
            return;
        }

        ConfigurationStatus indicatorStatus = checklistStatusMap.get(labelChecklistItemIndicator);
        overallConfigurationStatus = indicatorStatus;
        setHintPanelToMatchIndicatorStatus(indicatorStatus);
    }

    private void setHintPanelToMatchBadTarget() {
        labelHint.setText(
                Constant.messages.getString("authenticationhelper.checklist.hint.target"));
        btnSettings.setEnabled(false);
    }

    private void setHintPanelToMatchBadContext() {
        labelHint.setText(
                Constant.messages.getString("authenticationhelper.checklist.hint.context"));
        btnSettings.setEnabled(true);
        btnSettings.setToolTipText(
                Constant.messages.getString("authenticationhelper.checklist.btn.tooltip.context"));
        removeExistingActionListenersOfBtnSettings();
        btnSettings.addActionListener(
                e -> {
                    settingsBtnPressed();
                    createContextAndShowContextPropertiesDialog(
                            helperDialog.getTarget().getStartNode());
                });
    }

    private void updateStatusIconForChecklistItems() {
        checklistStatusMap.forEach(
                (checkListLabel, status) -> checkListLabel.setIcon(resolveStatusIcon(status)));
    }

    private Icon resolveStatusIcon(ConfigurationStatus status) {
        switch (status) {
            case BAD:
                return BAD_CONFIGURATION_ICON;
            case GOOD:
                return GOOD_CONFIGURATION_ICON;
            case MINIMAL:
                return MINIMAL_CONFIGURATION_ICON;
            case NOT_VALIDATED_YET:
                return NOT_VALIDATED_YET_ICON;
        }
        throw new IllegalArgumentException();
    }

    private void setHintPanelToMatchBadAuthenticationMethod() {
        labelHint.setText(
                Constant.messages.getString(
                        "authenticationhelper.checklist.hint.authenticationmethod"));
        btnSettings.setEnabled(true);
        btnSettings.setToolTipText(
                Constant.messages.getString(
                        "authenticationhelper.checklist.hint.authenticationmethod"));
        removeExistingActionListenersOfBtnSettings();
        btnSettings.addActionListener(
                e -> {
                    settingsBtnPressed();
                    showAuthenticationPropertiesDialog();
                });
    }

    private void setHintPanelToMatchBadUser() {
        labelHint.setText(Constant.messages.getString("authenticationhelper.checklist.hint.user"));
        btnSettings.setEnabled(true);
        btnSettings.setToolTipText(
                Constant.messages.getString("authenticationhelper.checklist.btn.tooltip.user"));
        removeExistingActionListenersOfBtnSettings();
        btnSettings.addActionListener(
                e -> {
                    settingsBtnPressed();
                    showUserPropertiesDialog();
                });
    }

    private void setHintPanelToMatchIndicatorStatus(ConfigurationStatus indicatorStatus) {
        String hintText;
        switch (indicatorStatus) {
            case MINIMAL:
                hintText =
                        Constant.messages.getString("authenticationhelper.checklist.hint.minimal");
                break;
            case BAD:
                hintText =
                        Constant.messages.getString(
                                "authenticationhelper.checklist.hint.indicator");
                break;
            case GOOD:
                hintText = Constant.messages.getString("authenticationhelper.checklist.hint.good");
                break;
            default:
                throw new IllegalArgumentException();
        }
        labelHint.setText(hintText);
        btnSettings.setEnabled(true);
        btnSettings.setToolTipText("Indicator properties");
        removeExistingActionListenersOfBtnSettings();
        btnSettings.addActionListener(
                e -> {
                    settingsBtnPressed();
                    showAuthenticationPropertiesDialog();
                });
    }

    private void resolveStausAndUpdateMap(JLabel labelChecklistItem, boolean isBadConfiguration) {
        ConfigurationStatus status =
                isBadConfiguration ? ConfigurationStatus.BAD : ConfigurationStatus.GOOD;
        checklistStatusMap.put(labelChecklistItem, status);
    }

    public ConfigurationStatus getConfigurationStatus() {
        return overallConfigurationStatus;
    }

    private Context getSelectedContext() {
        return helperDialog.getSelectedContext();
    }

    private void createContextAndShowContextPropertiesDialog(SiteNode startNode) {
        if (logger.isDebugEnabled()) {
            logger.debug(
                    "Automatically creating new context for the user for node "
                            + startNode.getName());
        }
        Context newContext = Model.getSingleton().getSession().getNewContext(startNode.getName());
        try {
            newContext.addIncludeInContextRegex(
                    new StructuralSiteNode(startNode).getRegexPattern());
            Model.getSingleton().getSession().saveContext(newContext);

            View.getSingleton()
                    .showSessionDialog(
                            Model.getSingleton().getSession(),
                            ContextIncludePanel.getPanelName(newContext.getIndex()));

        } catch (DatabaseException e) {
            // TODO: HELP: what should be the message passed to the user
            // if we are showing a warning dialog or something
        } catch (IllegalArgumentException e) {
            // TODO: thrown when creating a new context with the deleted context's name
        }
    }

    private void removeExistingActionListenersOfBtnSettings() {
        for (ActionListener listener : btnSettings.getActionListeners()) {
            btnSettings.removeActionListener(listener);
        }
    }

    private void settingsBtnPressed() {
        setStatusToNotValidatedYet();
        labelHint.setText(
                Constant.messages.getString("authenticationhelper.checklist.hint.refresh"));
    }

    private boolean indicatorDefined(Pattern indicator) {
        return indicator != null && !indicator.pattern().isEmpty();
    }

    private void setStatusToNotValidatedYet() {
        overallConfigurationStatus = ConfigurationStatus.NOT_VALIDATED_YET;

        checklistStatusMap.forEach(
                (k, v) -> {
                    checklistStatusMap.put(k, ConfigurationStatus.NOT_VALIDATED_YET);
                });

        updateStatusIconForChecklistItems();
    }

    private JButton getBtnSettings() {
        if (btnSettings == null) {
            btnSettings = new JButton();
            btnSettings.setIcon(
                    DisplayUtils.getScaledIcon(
                            new ImageIcon(
                                    AuthenticationConfigurationChecklistPanel.class.getResource(
                                            "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/gear.png"))));

            btnSettings.setPreferredSize(new Dimension(25, 25));
            btnSettings.setEnabled(false);
        }
        return btnSettings;
    }

    private void showUserPropertiesDialog() {
        View.getSingleton()
                .showSessionDialog(
                        Model.getSingleton().getSession(),
                        ContextUsersPanel.getPanelName(getSelectedContext().getIndex()));
    }

    private void showAuthenticationPropertiesDialog() {
        View.getSingleton()
                .showSessionDialog(Model.getSingleton().getSession(), getAuthenticationPaneName());
    }

    private String getAuthenticationPaneName() {
        return getSelectedContext().getIndex() + ": Authentication";
    }

    private AuthenticationMethod getConfiguredAuthenticationMethod() {
        if (getSelectedContext() == null) {
            return null;
        }
        return getSelectedContext().getAuthenticationMethod();
    }

    private User getSelectedUser() {
        return helperDialog.getSelectedUser();
    }
}
