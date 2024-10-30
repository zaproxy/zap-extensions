package org.zaproxy.addon.llm.ui;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.settings.LlmOptionsParam;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

import java.awt.Component;
import java.util.Set;

public class LlmReviewAlertMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;
    private ExtensionLlm extensionLlm;

    public LlmReviewAlertMenu(ExtensionLlm ext) {
        super(Constant.messages.getString("llm.menu.review.title"), true);
        this.extensionLlm = ext;
    }

    @Override
    public void performAction(Alert alert) {
        LlmOptionsParam llmOptionsParam = extensionLlm.getOptionsParam();
        LlmCommunicationService llmCommunicationService = new LlmCommunicationService(llmOptionsParam.getModelName(), llmOptionsParam.getApiKey(), llmOptionsParam.getEndpoint());
        try {
            llmCommunicationService.reviewAlert(alert);
        } catch (Exception e) {
            showWarningDialog(Constant.messages.getString("llm.reviewalert.error"));
            throw new RuntimeException(e);
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
            setEnabled(true);
            return true;
        }
        return false;
    }

    @Override
    public boolean isSafe() {
        return true;
    }

    public void showWarningDialog(String message) {
        View.getSingleton().showWarningDialog(message);
    }
}