/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.server.http;

import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;

/** A handler for local servers/proxies, ones managed by the user. */
public class LocalServerHandler extends MainProxyHandler {

    private static final Object SEMAPHORE_SINGLETON = new Object();

    private final SerialiseState serialiseState;
    private final Model model;

    /**
     * Constructs a {@code LocalServer} with the given properties.
     *
     * @param legacyHandler the handler for legacy (core) listeners.
     * @param handlers the message handlers.
     * @param serialiseState the serialisation state.
     * @param model the model to obtain the proxy excludes.
     */
    public LocalServerHandler(
            LegacyProxyListenerHandler legacyHandler,
            List<HttpMessageHandler> handlers,
            SerialiseState serialiseState,
            Model model) {
        super(legacyHandler, handlers);

        this.serialiseState = serialiseState;
        this.model = Objects.requireNonNull(model);
    }

    @Override
    protected HandlerResult processMessage(HttpMessage msg) {
        boolean excluded = isExcluded(msg);
        handlerContext.setExcluded(excluded);

        Object semaphore = !excluded && serialiseState.isSerialise() ? SEMAPHORE_SINGLETON : this;
        synchronized (semaphore) {
            return super.processMessage(msg);
        }
    }

    private boolean isExcluded(HttpMessage msg) {
        String uriString = msg.getRequestHeader().getURI().toString();
        for (String excludePattern :
                model.getOptionsParam().getGlobalExcludeURLParam().getTokensNames()) {
            if (uriString.matches(excludePattern)) {
                return true;
            }
        }

        for (String excludePattern : model.getSession().getExcludeFromProxyRegexs()) {
            if (uriString.matches(excludePattern)) {
                return true;
            }
        }
        return false;
    }

    /** Allows to provide the serialise state. */
    public interface SerialiseState {

        /**
         * Tells whether or not the serialisation is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise.
         */
        boolean isSerialise();
    }
}
