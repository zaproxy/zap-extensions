package org.zaproxy.addon.llm;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.alert.PopupMenuItemAlert;

import org.zaproxy.addon.llm.AnswerService;

import java.awt.Component;
import java.util.Set;

public class CheckLlmMenu extends PopupMenuItemAlert {

    private static final long serialVersionUID = 1L;
    private ExtensionLlm extensionLlm;
    private static final AnswerService answerService = new AnswerService();

    public CheckLlmMenu(ExtensionLlm ext) {
        super(Constant.messages.getString("llm.menu.review.title"), true);
        this.extensionLlm = ext;
    }

    @Override
    public void performAction(Alert alert) {
        if (alert.getSource().equals(Alert.Source.ACTIVE)
                || alert.getSource().equals(Alert.Source.PASSIVE)) {
            // review a single alert
            try {
                answerService.init();
                answerService.reviewAlert(alert);
            } catch (HttpMalformedHeaderException e) {
                throw new RuntimeException(e);
            } catch (DatabaseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    protected void performActions(Set<Alert> alerts) {
        // review all alerts
        try {
            answerService.init();
            answerService.reviewAlerts(alerts);
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        } catch (DatabaseException e) {
            throw new RuntimeException(e);
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
}