/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

/**
 * @since 0.21.0
 */
public interface ClientCallBackImplementor {

    /**
     * Context for a client callback request.
     *
     * @param initiator the {@link org.parosproxy.paros.network.HttpSender} initiator that launched
     *     the browser, or {@code -1} if unknown
     * @since 0.26.0
     */
    record ClientCallBackContext(int initiator) {}

    String getImplementorName();

    String handleCallBack(HttpMessage msg);

    /**
     * Handles a callback request from a browser connection.
     *
     * <p>The default implementation ignores {@link ClientCallBackContext} and delegates to {@link
     * #handleCallBack(HttpMessage)} for backward compatibility. Implementors that need the context
     * data must override this method.
     *
     * @param msg the callback request
     * @param context the callback context
     * @since 0.26.0
     */
    default String handleCallBack(HttpMessage msg, ClientCallBackContext context) {
        return handleCallBack(msg);
    }

    /**
     * This method will be removed soon.
     *
     * @deprecated
     */
    @Deprecated
    default void browserLaunched(SeleniumScriptUtils ssutils) {}

    @SuppressWarnings("deprecation")
    default void browserLaunched(ClientCallBackUtils ccbutils) {
        browserLaunched((SeleniumScriptUtils) ccbutils);
    }

    /**
     * @since 0.22.0
     */
    default void browserClosing(ClientCallBackUtils ccbutils) {}
}
