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

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class PersistentXSSCollectAndRefreshOriginalParamValues extends AbstractAppParamPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX =
            "ascanrules.persistentxsscollectandrefreshoriginalparamvalues.";

    public static final String XSS_STORAGE = "XSSStorage";

    private static Logger log =
            Logger.getLogger(PersistentXSSCollectAndRefreshOriginalParamValues.class);

    @Override
    public int getId() {
        return 40037;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
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
        // refresh the state of the website
        HttpMessage msg = getBaseMsg();
        try {
            HttpMessage msg1 = msg.cloneRequest();
            sendAndReceive(msg1, false);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        super.scan();
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        // TODO: should collect params only on POST/PUT when low or medium strength?
        if ((AlertThreshold.HIGH.equals(getAlertThreshold())
                        || AttackStrength.LOW.equals(getAttackStrength())
                        || AttackStrength.MEDIUM.equals(getAttackStrength()))
                && isScanningOnPath(msg, param, value)) {
            return;
        }

        if (value.length() > 0) {
            getStorage().addSeenValue(value);
        }
    }

    private boolean isScanningOnPath(HttpMessage msg, String param, String value) {
        // TODO: Should also consider the host? if the value is contained in host
        //  it will also cause a lot of requests
        String url = msg.getRequestHeader().getURI().getEscapedPath();
        if (param.equals(value) && url.contains(value)) {
            return true;
        }
        return false;
    }

    private PersistentXSSStorage getStorage() {
        PersistentXSSStorage storage;
        synchronized (getKb()) {
            Object obj = getKb().get(XSS_STORAGE);
            if (obj != null && obj instanceof PersistentXSSStorage) {
                storage = (PersistentXSSStorage) obj;
            } else {
                storage = new PersistentXSSStorage();
                getKb().add(XSS_STORAGE, storage);
            }
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
