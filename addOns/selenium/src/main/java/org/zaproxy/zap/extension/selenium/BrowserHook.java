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
package org.zaproxy.zap.extension.selenium;

/**
 * Once registered with SeleniumExtension will run whenever a browser is launched using selenium.
 */
public interface BrowserHook {

    void browserLaunched(SeleniumScriptUtils ssutils);

    /**
     * Called once all of the hooks (and any synchronous Selenium scripts) have run their {@link
     * #browserLaunched(SeleniumScriptUtils)}, i.e. when anything they do synchronously, such as
     * authenticating, has completed.
     *
     * <p>The default implementation does nothing.
     *
     * @param ssutils the utilities for the launched browser.
     * @since 15.61.0
     */
    default void browserReady(SeleniumScriptUtils ssutils) {}
}
