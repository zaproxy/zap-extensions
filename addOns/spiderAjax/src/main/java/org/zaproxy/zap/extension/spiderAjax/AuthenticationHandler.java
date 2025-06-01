/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import org.zaproxy.zap.users.User;

public interface AuthenticationHandler {

    /**
     * * Enables authentication handling for the given user, if the handler applies.
     *
     * @param user the user to authenticate for
     * @return true if this handler will handle authentication
     */
    boolean enableAuthentication(User user);

    /**
     * Disables authentication handling for the given user, if the handler applies.
     *
     * @param user the user
     * @return true if this handler was handling authentication for the user but is no longer doing
     *     so
     */
    boolean disableAuthentication(User user);
}
