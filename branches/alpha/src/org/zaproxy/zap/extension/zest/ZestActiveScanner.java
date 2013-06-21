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

package org.zaproxy.zap.extension.zest;

import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class ZestActiveScanner extends AbstractAppParamPlugin {

	private ExtensionZest extension = null;

    private static Logger log = Logger.getLogger(ZestActiveScanner.class);
	
    @Override
    public int getId() {
    	// TODO
        return 40099;
    }

    @Override
    public String getName() {
    	return "Zest Active Scanner (TBI)";	// TODO Constant.messages.getString("zest.activescanner.title");
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
        return "N/A";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "N/A";
    }

    @Override
    public String getReference() {
        return "N/A";
    }

    @Override
    public void init() {
    }

	private ExtensionZest getExtension() {
		if (extension == null) {
			extension = (ExtensionZest) Control.getSingleton().getExtensionLoader().getExtension(ExtensionZest.NAME);
		}
		return extension;
	}

    @Override
    public void scan(HttpMessage msg, String param, String value) {
		List<ZestScriptWrapper> scripts = this.getExtension().getAscanScripts();
			
		for (ZestScriptWrapper script : scripts) {
			try {
				HttpMessage msg1 = msg.cloneRequest();
				// This should then be replaced by the script
				this.setParameter(msg1, param, "{{target.value}}");
				extension.runScript(script, msg1);
			} catch (Exception e) {
				log.error(e.getMessage(), e);
			}
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_INFO;
	}

}
