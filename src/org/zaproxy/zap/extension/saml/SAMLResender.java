package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

import java.io.IOException;

public class SAMLResender {

    private static Logger log = Logger.getLogger(SAMLResender.class.getName());

    private SAMLResender() {

    }

    /**
     * Resend the message to the desired endpoint and get the response
     * @param msg The message to be sent
     */
    public static void resendMessage(final HttpMessage msg) throws SAMLException {
        HttpSender sender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true,
                HttpSender.MANUAL_REQUEST_INITIATOR);
        try {
            sender.sendAndReceive(msg, true);
            if (!msg.getResponseHeader().isEmpty()) {
                final ExtensionHistory extension = (ExtensionHistory) Control.getSingleton()
                        .getExtensionLoader().getExtension(ExtensionHistory.NAME);

                final int finalType = HistoryReference.TYPE_MANUAL;
                extension.addHistory(msg, finalType);
            }

        } catch (IOException e) {
            log.error(e.getMessage());
            throw new SAMLException("Message sending failed", e);
        }
    }
}
