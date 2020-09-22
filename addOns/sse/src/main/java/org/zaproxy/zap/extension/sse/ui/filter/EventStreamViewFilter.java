/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sse.ui.filter;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.sse.ServerSentEvent;

/**
 * Used as filter for the EventStream-Panel restricting types of events shown in the extensions'
 * tab.
 */
public class EventStreamViewFilter {

    private boolean isShowJustInScope = false;

    public void setShowJustInScope(boolean isShowJustInScope) {
        this.isShowJustInScope = isShowJustInScope;
    }

    public boolean getShowJustInScope() {
        return isShowJustInScope;
    }

    /** Resets this filter. Events will no longer be deny listed. */
    public void reset() {}

    /**
     * Checks if the given entry is affected by this filter, i.e. is filtered out.
     *
     * @param event
     * @return True if the given entry is filtered out, false if valid.
     */
    public boolean isDenylisted(ServerSentEvent event) {
        if (isShowJustInScope && !event.isInScope()) {
            return true;
        }

        return false;
    }

    /** @return short description of applied filter */
    public String toShortString() {
        return toString(false);
    }

    /** @return description of applied filter */
    public String toLongString() {
        return toString(true);
    }

    /**
     * @param shouldIncludeValues
     * @return description of the applied filters
     */
    private String toString(boolean shouldIncludeValues) {
        StringBuilder sb = new StringBuilder();

        boolean empty = true;

        sb.insert(0, " ");

        if (empty) {
            sb.insert(0, Constant.messages.getString("sse.filter.label.off"));
        } else {
            sb.insert(0, Constant.messages.getString("sse.filter.label.on"));
        }

        sb.insert(0, " ");
        sb.insert(0, Constant.messages.getString("sse.filter.label.filter"));

        return sb.toString();
    }
}
