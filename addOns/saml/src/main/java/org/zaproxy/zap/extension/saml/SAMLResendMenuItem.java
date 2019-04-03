package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.saml.ui.SamlManualEditor;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

public class SAMLResendMenuItem extends PopupMenuItemHttpMessageContainer {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(SAMLResendMenuItem.class); 

    public SAMLResendMenuItem(String label) {
        super(label);
    }

    @Override
    public void performAction(HttpMessage httpMessage) {
        if (!SAMLUtils.hasSAMLMessage(httpMessage)) {
            View.getSingleton().showWarningDialog("Not a valid SAML request");
            return;
        }
        try {
            SamlManualEditor editor = new SamlManualEditor(new SAMLMessage(httpMessage));
            editor.setVisible(true);
        } catch (SAMLException e) {
            LOGGER.error("Failed to show SAML manual editor: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker, HttpMessageContainer httpMessageContainer) {
        //TODO filter out the unnecessary invokers
        return true;
    }

}
