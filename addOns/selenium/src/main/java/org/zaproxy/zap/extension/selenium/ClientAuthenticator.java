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
package org.zaproxy.zap.extension.selenium;

import org.openqa.selenium.WebDriver;
import org.zaproxy.zap.users.User;

/**
 * Interface for authentication methods that can authenticate a user in a browser (WebDriver).
 *
 * @since 15.44.0
 */
public interface ClientAuthenticator {

    /**
     * Authenticates the given user in the browser controlled by the WebDriver.
     *
     * @param webDriver the WebDriver controlling the browser
     * @param user the user to authenticate
     * @return true if authentication was successful, false otherwise
     */
    boolean authenticate(WebDriver webDriver, User user);
}
