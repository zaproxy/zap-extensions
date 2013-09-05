package org.zaproxy.zap.extension.saml;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.saml.ui.SAMLManualRequestEditorFrame;
import org.zaproxy.zap.view.PopupMenuHttpMessage;

public class SAMLResendMenuItem extends PopupMenuHttpMessage {

    public SAMLResendMenuItem(String label) {
        super("Resend...");
    }

    @Override
    public void performAction(HttpMessage httpMessage) throws Exception {
        if(!SAMLUtils.hasSAMLMessage(httpMessage)){
            View.getSingleton().showWarningDialog("Not a valid SAML request");
            return;
        }
        SAMLManualRequestEditorFrame editor = new SAMLManualRequestEditorFrame(httpMessage);
        editor.showUI();
    }

    @Override
    public boolean isEnableForInvoker(Invoker invoker) {
        //TODO filter out the unnecessary invokers
        return true;
    }

}
