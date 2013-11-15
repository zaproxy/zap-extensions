/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.plugnhack.fuzz;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.AbstractFuzzProcess;
import org.zaproxy.zap.extension.fuzz.FuzzResult;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.plugnhack.httppanel.views.ClientFuzzableTextMessage;

/**
 * On process is created per fuzz string.
 */
public class ClientMessageFuzzProcess extends AbstractFuzzProcess {

    private static final Logger logger = Logger.getLogger(ClientMessageFuzzProcess.class);

    private ExtensionPlugNHack extension;
    private ClientFuzzableTextMessage fuzzableMessage;

    public ClientMessageFuzzProcess(ExtensionPlugNHack extension, ClientFuzzableTextMessage fuzzableMessage) {
    	this.extension = extension;
        this.fuzzableMessage = fuzzableMessage;
    }

    @Override
    public FuzzResult fuzz(String fuzz) {
        ClientMessageFuzzResult fuzzResult = new ClientMessageFuzzResult();
        fuzzResult.setFuzz(fuzz);
        
        ClientFuzzMessage msg;
        
        try {
            // inject the payload
            msg = fuzzableMessage.fuzz(fuzz);
        } catch(Exception e) {
            logger.error(e.getMessage(), e);
            
            fuzzResult.setMessage(fuzzableMessage.getMessage());

            fuzzResult.setState(FuzzResult.State.ERROR);
            
            return fuzzResult;
        }
        
        fuzzResult.setMessage(msg);
        
        try {
        	// Wait for any previous messages to be sent
        	// TODO how to interupt this on stop?
        	while (this.extension.isPendingMessages(msg.getClientId())) {
        		Thread.sleep(100);
        	}
        	
        	// send the payload
        	this.extension.resend(msg);
        	
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            fuzzResult.setState(FuzzResult.State.ERROR);
        }
        
        return fuzzResult;
    }

}
