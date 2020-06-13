/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import static org.zaproxy.zap.extension.ascanrules.PersistentXSSCollectAndRefreshOriginalParamValues.XSS_STORAGE;

import java.util.Set;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class PersistentXSSFindPossibleSinks extends AbstractAppPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.persistentxssfindpossiblesinks.";

    private static Logger log = Logger.getLogger(PersistentXSSFindPossibleSinks.class);

    @Override
    public int getId() {
        return 40039;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String[] getDependency() {
        return new String[] {"PersistentXSSCollectAndRefreshOriginalParamValues"};
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "misc");
    }

    @Override
    public void scan() {
        HttpMessage msg = getBaseMsg();
        try {
            HttpMessage msg1 = msg.cloneRequest();
            sendAndReceive(msg1, false);
            findPossibleSinks(msg1);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    private void findPossibleSinks(HttpMessage msg) {
        PersistentXSSStorage storage = getStorage();
        String msgBody = msg.getResponseBody().toString();
        Set<String> valuesSeenInResponseBody = storage.getSeenValuesContainedInString(msgBody);

        for (String value : valuesSeenInResponseBody) {
            storage.addPossibleSinkForValue(value, msg);
        }
    }

    private PersistentXSSStorage getStorage() {
        PersistentXSSStorage storage;
        Object obj = getKb().get(XSS_STORAGE);
        if (obj instanceof PersistentXSSStorage) {
            storage = (PersistentXSSStorage) obj;
        } else {
            throw new IllegalStateException(
                    "The XSS_STORAGE Should have been initialized by the PersistentXSSCollectAndRefreshOriginalParamValues");
        }
        return storage;
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
