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
package org.zaproxy.zap.extension.ascanrules;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class TestPersistentXSSSpider extends AbstractAppPlugin {

    private static Logger log = Logger.getLogger(TestPersistentXSSSpider.class);

    @Override
    public int getId() {
        return 40017;
    }

    @Override
    public String getName() {
        AscanUtils.registerI18N();
        return Constant.messages.getString("ascanrules.pxss.spider.name");
    }

    @Override
    public String[] getDependency() {
        return new String[]{"TestPersistentXSSPrime"};
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
    public void scan() {

        HttpMessage msg = getBaseMsg();
        try {
            HttpMessage msg1 = msg.cloneRequest();
            sendAndReceive(msg1, false);
            PersistentXSSUtils.testForSink(msg1);

        } catch (Exception e) {
			log.error(e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public int getCweId() {
        return 79;
    }

    @Override
    public int getWascId() {
        return 8;
    }
}
