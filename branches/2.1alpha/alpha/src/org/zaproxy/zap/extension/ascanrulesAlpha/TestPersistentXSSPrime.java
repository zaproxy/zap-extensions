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

package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class TestPersistentXSSPrime extends AbstractAppParamPlugin {

    private static Logger log = Logger.getLogger(TestPersistentXSSPrime.class);
	
    @Override
    public int getId() {
        return 40012;
    }

    @Override
    public String getName() {
    	AscanUtils.registerI18N();
    	return Constant.messages.getString("ascanalpha.pxss.prime.name");
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
    
    @Override
    public void scan(HttpMessage msg, String param, String value) {
		try {
			HttpMessage msg1 = msg.cloneRequest();
			this.setParameter(msg1, param, PersistentXSSUtils.getUniqueValue(msg1, param));
			if (log.isDebugEnabled()) {
				log.debug("Prime msg=" + msg1.getRequestHeader().getURI() + " param=" + param);
			}
		    sendAndReceive(msg1, false);
		} catch (Exception e) {
			// TODO
	    	System.out.println("Exception " + e);
		    e.printStackTrace();
		}
	}

	@Override
	public int getRisk() {
		return Alert.RISK_INFO;
	}

}
