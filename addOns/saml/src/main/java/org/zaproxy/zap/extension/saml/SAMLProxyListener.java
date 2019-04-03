package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;

public class SAMLProxyListener implements ProxyListener {

    private SAMLConfiguration configuration;

    protected final static Logger log = Logger.getLogger(SAMLProxyListener.class.getName());

    public SAMLProxyListener() {
        configuration = SAMLConfiguration.getInstance();
    }

    /**
     * Check whether the passive listener is activated. If deactivated the requests will be unchanged even the
     * attributes to be changed, exists in the message
     */
    public boolean isActive() {
        return configuration.getAutoChangeEnabled();
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage message) {
        if (isActive() && SAMLUtils.hasSAMLMessage(message)) {
            try {
                SAMLMessage samlMessage = new SAMLMessage(message);

                //change the params
                for (Attribute attribute : configuration.getAutoChangeAttributes()) {
                    String value = attribute.getValue().toString();
                    boolean changed = samlMessage.changeAttributeValueTo(attribute.getName(), value);
                    if (changed) {
                        log.debug(attribute.getName() + ": value changed to " + value);
                    }
                }

                //change the original message
                HttpMessage changedMessege = samlMessage.getChangedMessage();
                if (changedMessege != message) {
                    //check for reference, if they are same the message is already changed,
                    // else the header and body are changed
                    message.setRequestBody(changedMessege.getRequestBody());
                    message.setRequestHeader(changedMessege.getRequestHeader());
                }

            } catch (SAMLException ignored) {
            }
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage message) {
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }
}
