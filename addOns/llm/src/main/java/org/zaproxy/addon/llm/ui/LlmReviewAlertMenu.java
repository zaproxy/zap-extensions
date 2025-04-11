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
package org.zaproxy.addon.llm.ui;

import java.awt.Component;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsParam;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

@SuppressWarnings("serial")
public class LlmReviewAlertMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;
    private ExtensionLlm extensionLlm;
    private static final Logger LOGGER = LogManager.getLogger(LlmReviewAlertMenu.class);


    public LlmReviewAlertMenu(ExtensionLlm ext) {
        super(Constant.messages.getString("llm.menu.review.title"), true);
        this.extensionLlm = ext;
    }

    @Override
    public void performAction(Alert alert) {


        try {
            // Prevent GUI from freezing using threads
            final Runnable r = new Runnable() {
                @Override
                public void run() {
                    reviewAlert(alert);
                }
            };

            // Start a new thread to run the reviewAlert method
            new Thread(r).start();
        } catch (Exception e) {
            showWarningDialog(Constant.messages.getString("llm.reviewalert.error"));
            LOGGER.error(e);
        }
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
            setEnabled(extensionLlm.isConfigured());
            return true;
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    private void reviewAlert(Alert alert){
        LlmOptionsParam llmOptionsParam = extensionLlm.getOptionsParam();
        LlmCommunicationService llmCommunicationService =
                new LlmCommunicationService(
                        llmOptionsParam.getModelName(),
                        llmOptionsParam.getApiKey(),
                        llmOptionsParam.getEndpoint());
        llmCommunicationService.reviewAlert(alert);
    }

    public void showWarningDialog(String message) {
        View.getSingleton().showWarningDialog(message);
    }
}
