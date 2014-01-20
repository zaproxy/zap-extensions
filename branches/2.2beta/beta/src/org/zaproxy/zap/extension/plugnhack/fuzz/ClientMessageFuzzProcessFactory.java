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

import org.zaproxy.zap.extension.fuzz.FuzzProcess;
import org.zaproxy.zap.extension.fuzz.FuzzProcessFactory;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.plugnhack.httppanel.views.ClientFuzzableTextMessage;

public class ClientMessageFuzzProcessFactory implements FuzzProcessFactory {

	private ExtensionPlugNHack extension;
    private ClientFuzzableTextMessage fuzzableMessage;

    public ClientMessageFuzzProcessFactory(ExtensionPlugNHack extension, ClientFuzzableTextMessage fuzzableMessage) {
    	this.extension = extension;
        this.fuzzableMessage = fuzzableMessage;
    }
    
    @Override
    public FuzzProcess getFuzzProcess(String fuzz) {
        FuzzProcess fuzzProcess = new ClientMessageFuzzProcess(extension, fuzzableMessage);
        fuzzProcess.setFuzz(fuzz);
        return fuzzProcess;
    }
}
