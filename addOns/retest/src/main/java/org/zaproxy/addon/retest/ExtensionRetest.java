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
package org.zaproxy.addon.retest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionRetest extends ExtensionAdaptor {

    public static final String NAME = "ExtensionRetest";

    private RetestMenu retestMenu;
    private ZapMenuItem menuItemRetest;
    private RetestDialog retestDialog;

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionAutomation.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionRetest() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        RetestAPI retestApi = new RetestAPI(this);
        extensionHook.addApiImplementor(retestApi);

        if (hasView()) {
            extensionHook.addSessionListener(new SessionChangedListenerImpl());
            extensionHook.getHookMenu().addPopupMenuItem(getRetestMenu());
            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemRetest());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        disposeDialog();
    }

    private void disposeDialog() {
        if (retestDialog != null) {
            retestDialog.dispose();
            retestDialog = null;
        }
    }

    private RetestMenu getRetestMenu() {
        if (retestMenu == null) {
            retestMenu = new RetestMenu(this);
        }
        return retestMenu;
    }

    private ZapMenuItem getMenuItemRetest() {
        if (menuItemRetest == null) {
            menuItemRetest = new ZapMenuItem("retest.menu.title");
            menuItemRetest.addActionListener(actionEvent -> addAlertToDialog(null));
        }
        return menuItemRetest;
    }

    public void addAlertToDialog(Alert alert) {
        if (retestDialog == null) {
            retestDialog = new RetestDialog(this, getView().getMainFrame(), false);
        }
        if (alert != null) {
            retestDialog.addAlert(alert);
        }
        retestDialog.setVisible(true);
    }

    public AutomationPlan getPlanForAlerts(List<AlertData> alerts) {
        RetestPlanGenerator retestGen = new RetestPlanGenerator(alerts);
        return retestGen.getPlan();
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("retest.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("retest.desc");
    }

    public static boolean testsForAlert(AutomationAlertTest test, AlertData data) {
        AutomationAlertTest.Data testData = test.getData();
        return data.getScanRuleId() == testData.getScanRuleId()
                && data.getAlertName().equals(testData.getAlertName())
                && data.getUrl().equals(testData.getUrl())
                && data.getMethod().equals(testData.getMethod())
                && data.getAttack().equals(testData.getAttack())
                && data.getParam().equals(testData.getParam())
                && data.getEvidence().equals(testData.getEvidence())
                && data.getConfidence().equals(testData.getConfidence())
                && data.getRisk().equals(testData.getRisk())
                && data.getOtherInfo().equals(testData.getOtherInfo());
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Mode mode) {}

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionAboutToChange(Session session) {
            disposeDialog();
        }
    }
}
