package org.zaproxy.zap.extension.saml;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;

import java.util.Set;

public class SAMLProxyListener implements ProxyListener {

    private boolean active;
    private Set<Attribute> autoChangeAttribs;

    protected static Logger log = Logger.getLogger(SAMLProxyListener.class.getName());

    public SAMLProxyListener() {
        setActive(SAMLConfiguration.getConfigurations().getAutoChangeEnabled());
    }

    public void setActive(boolean value) {
        active = value;
        if (active && autoChangeAttribs == null) {
            loadAutoChangeAttributes();
        }
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage message) {
        if (active && SAMLUtils.hasSAMLMessage(message)) {
            try {
                SAMLMessage samlMessage = new SAMLMessage(message);

                //change the params
                for (Attribute attribute : autoChangeAttribs) {
                    String value = attribute.getValue().toString();
                    boolean changed = samlMessage.changeAttributeValueTo(attribute.getName(), value);
                    if(changed){
                        log.debug(attribute.getName()+": value changed to "+value);
                    }
                }

                //change the original message
                HttpMessage changedMessege = samlMessage.getChangedMessage();
                if(changedMessege!=message){
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

    public void loadAutoChangeAttributes() {
        autoChangeAttribs = SAMLConfiguration.getConfigurations().getAutoChangeAttributes();
    }
}
