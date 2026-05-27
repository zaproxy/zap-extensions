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
package org.zaproxy.addon.client.spider;

import java.util.Collections;
import java.util.List;
import lombok.Builder;
import lombok.Getter;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/** Immutable options for a client spider scan. */
@Getter
@Builder(toBuilder = true, setterPrefix = "set", builderClassName = "Builder")
public class ScanOptions {

    private final Context context;
    private final User user;
    private final boolean subtreeOnly;

    /**
     * When {@code true} the scan is controlled externally: results are not shown in the GUI and
     * scan notifications are not emitted.
     */
    @Builder.Default private final boolean externalControl = false;

    @Builder.Default private final int initiator = HttpSender.CLIENT_SPIDER_INITIATOR;

    /**
     * The {@code HttpSender} to use for browser proxy traffic. If not set a new {@code HttpSender}
     * is created using {@link #initiator}.
     *
     * @since 0.26.0
     */
    private final HttpSender httpSender;

    @Builder.Default private final int hrefType = HistoryReference.TYPE_CLIENT_SPIDER;

    @Builder.Default private final int tmpHrefType = HistoryReference.TYPE_CLIENT_SPIDER_TEMPORARY;

    @Builder.Default private final String threadPrefix = "ZAP-ClientSpiderThreadPool-";

    /**
     * Browser extension names to include when launching browsers, even if disabled in the Selenium
     * options.
     *
     * @since 0.26.0
     */
    @Builder.Default private final List<String> includeExtensions = Collections.emptyList();

    /**
     * Browser extension names to exclude when launching browsers, even if enabled in the Selenium
     * options.
     *
     * @since 0.26.0
     */
    @Builder.Default private final List<String> excludeExtensions = Collections.emptyList();

    /** A builder of options. */
    public static class Builder {

        /**
         * Sets the thread name prefix.
         *
         * <p>Default value: {@code ZAP-ClientSpiderThreadPool-}.
         *
         * @param threadPrefix the thread name prefix.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the prefix is {@code null} or blank.
         */
        public Builder setThreadPrefix(String threadPrefix) {
            if (threadPrefix == null || threadPrefix.isBlank()) {
                throw new IllegalArgumentException("threadPrefix must not be null or blank");
            }
            this.threadPrefix$value = threadPrefix;
            this.threadPrefix$set = true;
            return this;
        }
    }
}
