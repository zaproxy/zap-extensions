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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import org.zaproxy.zap.extension.fuzz.FuzzerOptions;

public class HttpFuzzerOptions extends FuzzerOptions {

    private final boolean followRedirects;
    private final boolean showRedirectMessages;
    private final int maximumRedirects;

    public HttpFuzzerOptions(
            FuzzerOptions baseOptions,
            boolean followRedirects,
            boolean showRedirectMessages,
            int maximumRedirects) {
        super(baseOptions);

        this.followRedirects = followRedirects;
        this.showRedirectMessages = showRedirectMessages;
        this.maximumRedirects = maximumRedirects;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public boolean isShowRedirectMessages() {
        return showRedirectMessages;
    }

    public int getMaximumRedirects() {
        return maximumRedirects;
    }
}
