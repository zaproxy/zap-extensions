/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.llm;

import java.awt.Component;
import java.util.Set;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;
import org.zaproxy.zap.utils.Stats;

@SuppressWarnings("serial")
public class LlmReviewAlertMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;

    private ExtensionLlm extLlm;
    private LlmActionReviewAlert actionReviewAlert;

    public LlmReviewAlertMenu(ExtensionLlm extLlm, ExtensionAlert extAlert) {
        super(Constant.messages.getString("alertFilters.llm.menu.review.title"), true);
        this.extLlm = extLlm;
        actionReviewAlert = new LlmActionReviewAlert(extLlm, extAlert);
    }

    @Override
    public void performAction(Alert alert) {
        new Thread(
                        () -> {
                            try {
                                actionReviewAlert.reviewAlert(alert);
                            } catch (Exception e) {
                                Stats.incCounter("stats.llm.alertreview.result.error");
                                View.getSingleton()
                                        .showWarningDialog(
                                                Constant.messages.getString(
                                                        "alertFilters.llm.reviewalert.error"));
                            }
                        },
                        "ZAP-LLM-Alert-Review")
                .start();
    }

    @Override
    protected void performActions(Set<Alert> alerts) {
        for (Alert alert : alerts) {
            performAction(alert);
        }
    }

    @Override
    public boolean isEnableForComponent(Component invoker) {
        if (super.isEnableForComponent(invoker)) {
            setEnabled(extLlm.isConfigured());
            this.setToolTipText(this.isEnabled() ? null : extLlm.getCommsIssue());
            return true;
        }
        return false;
    }

    @Override
    public String getParentMenuName() {
        return Constant.messages.getString("llm.aiassisted.popup");
    }

    @Override
    public boolean isSubMenu() {
        return true;
    }

    @Override
    public boolean isSafe() {
        return true;
    }
}
