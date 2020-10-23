/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.callback.CallbackImplementor;
import org.zaproxy.zap.extension.callback.ExtensionCallback;

/**
 * General Abstract class for Challenge/Response Active Plugin management
 *
 * @author yhawke (2014)
 */
public abstract class ChallengeCallbackImplementor implements CallbackImplementor {

    // The default expiration time for each callback (in millisecs)
    private static final long CALLBACK_EXPIRE_TIME = 2 * 60 * 1000L;

    // Internal logger
    private static final Logger logger = Logger.getLogger(ChallengeCallbackImplementor.class);

    // The registered callbacks for this API
    // Use a synchronized collection
    private final Map<String, RegisteredCallback> regCallbacks =
            Collections.synchronizedMap(new TreeMap<String, RegisteredCallback>());

    private static ExtensionCallback extCallback;

    /** Default contructor */
    public ChallengeCallbackImplementor() {
        if (getExtensionCallback() != null) {
            getExtensionCallback().registerCallbackImplementor(this);
        }
    }

    /**
     * Implements this to give back the specific shortcut
     *
     * @return the shortcut path to call the API
     */
    public abstract String getPrefix();

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

    /**
     * @param challenge
     * @return
     */
    public String getCallbackUrl(String challenge) {
        return getExtensionCallback().getCallbackAddress() + getPrefix() + "/" + challenge;
    }

    /**
     * @param msg
     * @return
     * @throws ApiException
     */
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
                rcback.getPlugin().notifyCallback(challenge, rcback.getAttackMessage());

                // OK we consumed it so it's time to clean
                regCallbacks.remove(challenge);

            } else {
                // Maybe we've a lot of dirty entries
                cleanExpiredCallbacks();
            }

        } catch (URIException e) {
            logger.warn(e.getMessage(), e);
        }
    }

    /**
     * @param challenge
     * @param plugin
     * @param attack
     */
    public void registerCallback(
            String challenge, ChallengeCallbackPlugin plugin, HttpMessage attack) {
        // Maybe we'va a lot of dirty entries
        cleanExpiredCallbacks();

        // Already synchronized (no need for a monitor)
        regCallbacks.put(challenge, new RegisteredCallback(plugin, attack));
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
     * Only for use in unit tests
     *
     * @param extCallback
     */
    protected static void setExtensionCallback(ExtensionCallback ext) {
        extCallback = ext;
    }

    /** */
    private static class RegisteredCallback {
        private ChallengeCallbackPlugin plugin;
        private HistoryReference hRef;
        private long timeStamp;

        public RegisteredCallback(ChallengeCallbackPlugin plugin, HttpMessage msg) {
            this.plugin = plugin;
            this.timeStamp = System.currentTimeMillis();

            try {
                // Generate an HistoryReference object
                this.hRef =
                        new HistoryReference(
                                Model.getSingleton().getSession(),
                                HistoryReference.TYPE_TEMPORARY,
                                msg);

            } catch (DatabaseException | HttpMalformedHeaderException ex) {
            }
        }

        public ChallengeCallbackPlugin getPlugin() {
            return plugin;
        }

        public HttpMessage getAttackMessage() {
            try {
                if (hRef != null) {
                    return hRef.getHttpMessage();
                }

            } catch (DatabaseException | HttpMalformedHeaderException ex) {
            }

            return null;
        }

        public long getTimestamp() {
            return timeStamp;
        }
    }
}
