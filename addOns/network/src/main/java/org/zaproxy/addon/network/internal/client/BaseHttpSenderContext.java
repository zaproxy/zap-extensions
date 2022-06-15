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
package org.zaproxy.addon.network.internal.client;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.client.core.HttpSenderContext;
import org.zaproxy.zap.users.User;

public abstract class BaseHttpSenderContext implements HttpSenderContext {

    private final HttpSender parent;
    private final int initiator;

    private boolean followRedirects;
    private User user;
    private boolean useCookies;
    private boolean useGlobalState;
    private int maxRedirects;
    private int maxRetriesOnIoError;
    private boolean removeUserDefinedAuthHeaders;

    protected BaseHttpSenderContext(HttpSender parent, int initiator) {
        this.parent = parent;
        this.initiator = initiator;
        this.maxRedirects = 100;
        setMaxRetriesOnIoError(3);
    }

    public int getInitiator() {
        return initiator;
    }

    public HttpSender getParent() {
        return parent;
    }

    @Override
    public void setUseGlobalState(boolean use) {
        useGlobalState = use;
    }

    public boolean isUseGlobalState() {
        return useGlobalState;
    }

    @Override
    public void setUseCookies(boolean use) {
        useCookies = use;
    }

    public boolean isUseCookies() {
        return useCookies;
    }

    @Override
    public void setFollowRedirects(boolean follow) {
        followRedirects = follow;
    }

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    @Override
    public void setMaxRedirects(int max) {
        if (max < 0) {
            throw new IllegalArgumentException("The maximum must be greater or equal to zero.");
        }
        maxRedirects = max;
    }

    public int getMaxRedirects() {
        return maxRedirects;
    }

    @Override
    public void setMaxRetriesOnIoError(int max) {
        if (max < 0) {
            throw new IllegalArgumentException("The maximum must be greater or equal to zero.");
        }
        maxRetriesOnIoError = max;
    }

    public int getMaxRetriesOnIoError() {
        return maxRetriesOnIoError;
    }

    @Override
    public void setRemoveUserDefinedAuthHeaders(boolean remove) {
        removeUserDefinedAuthHeaders = remove;
    }

    public boolean isRemoveUserDefinedAuthHeaders() {
        return removeUserDefinedAuthHeaders;
    }

    @Override
    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public User getUser(HttpMessage msg) {
        if (user != null) {
            return user;
        }
        return msg.getRequestingUser();
    }
}
