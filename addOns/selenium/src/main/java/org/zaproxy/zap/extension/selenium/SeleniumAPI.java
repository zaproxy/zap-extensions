/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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

import org.zaproxy.zap.extension.api.ApiImplementor;

/** The Selenium API. */
public class SeleniumAPI extends ApiImplementor {

    private static final String API_PREFIX = "selenium";

    /** Provided only for API client generator usage. */
    public SeleniumAPI() {
        // Nothing to do.
    }

    /**
     * Constructs a {@code SeleniumAPI} with the given {@code options} exposed through the API.
     *
     * @param options the options that will be exposed through the API
     */
    public SeleniumAPI(SeleniumOptions options) {
        addApiOptions(options);
    }

    @Override
    public String getPrefix() {
        return API_PREFIX;
    }
}
