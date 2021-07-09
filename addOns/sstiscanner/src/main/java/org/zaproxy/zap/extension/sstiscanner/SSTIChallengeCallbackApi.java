/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.sstiscanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.callback.CallbackImplementor;
import org.zaproxy.zap.extension.callback.ExtensionCallback;

/** @author DiogoMRSilva (2018) based on XXE plugin(yhawke) */
public class SSTIChallengeCallbackApi implements CallbackImplementor {

    private static final String PREFIX = "SSTI";
    private static final int CHALLENGE_LENGTH = 6;

    // The default expiration time for each callback (in millisecs)
    private static final long CALLBACK_EXPIRE_TIME = TimeUnit.MINUTES.toMillis(2);

    // Internal logger
    private static final Logger LOGGER = Logger.getLogger(SSTIChallengeCallbackApi.class);

    // The registered callbacks for this API
    // Use a synchronized collection
    private final Map<String, RegisteredCallback> regCallbacks =
            Collections.synchronizedMap(new TreeMap<String, RegisteredCallback>());

    private static ExtensionCallback extCallback;

    /** Default contructor */
    public SSTIChallengeCallbackApi() {
        if (getExtensionCallback() != null) {
            getExtensionCallback().registerCallbackImplementor(this);
        }
    }

    @Override
    public List<String> getCallbackPrefixes() {
        List<String> list = new ArrayList<String>();
        list.add(getPrefix());
        return list;
    }

    /**
     * Expire callbacks cleaning method. When called it remove from the received callbacks list all
     * the sent challenge which haven't received any answer till now according to an expiring
     * constraint. Currently the cleaning is done for every new inserting and every received
     * callback, but it can be done also with a scheduled cleaning thread if the number of items is
     * memory and time consuming... Maybe to be understood in the future.
     */
    public void cleanExpiredCallbacks() {
        long now = System.currentTimeMillis();

        // Cuncurrency could be possible for multiple instantiations
        synchronized (regCallbacks) {
            Iterator<Map.Entry<String, RegisteredCallback>> it = regCallbacks.entrySet().iterator();
            Map.Entry<String, RegisteredCallback> entry;

            while (it.hasNext()) {
                entry = it.next();
                if (now - entry.getValue().getTimestamp() > CALLBACK_EXPIRE_TIME) {
                    it.remove();
                }
            }
        }
    }

    public String getCallbackUrl(String challenge) {
        return getExtensionCallback().getCallbackAddress() + getPrefix() + "/" + challenge;
    }

    @Override
    public void handleCallBack(HttpMessage msg) {
        // We've to look at the name and verify if the challenge has
        // been registered by one of the executed plugins
        try {
            String path = msg.getRequestHeader().getURI().getPath();
            String challenge = path.substring(path.indexOf(getPrefix()) + getPrefix().length() + 1);
            if (challenge.charAt(challenge.length() - 1) == '/') {
                challenge = challenge.substring(0, challenge.length() - 1);
            }

            RegisteredCallback rcback = regCallbacks.get(challenge);

            if (rcback != null) {
                rcback.getPlugin()
                        .notifyCallback(
                                rcback.getAttackMessage(),
                                rcback.getParamName(),
                                rcback.getPayload());

                // OK we consumed it so it's time to clean
                regCallbacks.remove(challenge);

            } else {
                // Maybe we've a lot of dirty entries
                cleanExpiredCallbacks();
            }

        } catch (URIException e) {
            LOGGER.warn(e.getMessage(), e);
        }
    }

    protected static ExtensionCallback getExtensionCallback() {
        if (extCallback == null) {
            extCallback =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionCallback.class);
        }
        return extCallback;
    }

    /**
     * Implements this to give back the specific shortcut
     *
     * @return the shortcut path to call the API
     */
    public String getPrefix() {
        return PREFIX;
    }

    public String generateRandomChallenge() {
        return randomString(CHALLENGE_LENGTH);
    }

    private String randomString(int length) {
        String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        return SSTIUtils.randomStringFromAlphabet(alphabet, length);
    }

    public void registerCallback(
            String challenge,
            SSTIBlindScanner plugin,
            HttpMessage attack,
            String payload,
            String paramName) {

        // Maybe we'va a lot of dirty entries
        cleanExpiredCallbacks();

        // Already synchronized (no need for a monitor)
        regCallbacks.put(challenge, new RegisteredCallback(plugin, attack, payload, paramName));
    }

    private static class RegisteredCallback {
        private SSTIBlindScanner plugin;
        private HttpMessage msg;
        private String payload;
        private String paramName;
        private long timeStamp;

        public RegisteredCallback(
                SSTIBlindScanner plugin, HttpMessage msg, String payload, String paramName) {
            this.plugin = plugin;
            this.timeStamp = System.currentTimeMillis();
            this.msg = msg;
            this.paramName = paramName;
            this.payload = payload;
        }

        public SSTIBlindScanner getPlugin() {
            return plugin;
        }

        public HttpMessage getAttackMessage() {
            if (msg != null) {
                return msg;
            }
            return null;
        }

        public long getTimestamp() {
            return timeStamp;
        }

        public String getPayload() {
            return payload;
        }

        public String getParamName() {
            return paramName;
        }
    }
}
