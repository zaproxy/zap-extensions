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

import java.util.HashMap;
import java.util.Map;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpSenderContext;
import org.zaproxy.zap.users.User;

public abstract class BaseHttpSenderContext implements HttpSenderContext {

    static final String INITIATOR_FIELD = "initiator";
    private static final String FOLLOW_REDIRECTS_FIELD = "followRedirects";
    private static final String USER_FIELD = "user";
    private static final String USE_COOKIES_FIELD = "useCookies";
    private static final String USE_GLOBAL_STATE_FIELD = "useGlobalState";
    private static final String MAX_REDIRECTS_FIELD = "maxRedirects";
    private static final String MAX_RETRIES_ON_IO_ERROR_FIELD = "maxRetriesOnIoError";
    private static final String REMOVE_USER_DEFINED_AUTH_HEADERS_FIELD =
            "removeUserDefinedAuthHeaders";

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

    Map<String, Object> toMap() {
        Map<String, Object> data = new HashMap<>();
        data.put(INITIATOR_FIELD, initiator);
        data.put(FOLLOW_REDIRECTS_FIELD, followRedirects);
        data.put(USER_FIELD, user);
        data.put(USE_COOKIES_FIELD, useCookies);
        data.put(USE_GLOBAL_STATE_FIELD, useGlobalState);
        data.put(MAX_REDIRECTS_FIELD, maxRedirects);
        data.put(MAX_RETRIES_ON_IO_ERROR_FIELD, maxRetriesOnIoError);
        data.put(REMOVE_USER_DEFINED_AUTH_HEADERS_FIELD, removeUserDefinedAuthHeaders);
        return data;
    }

    void fromMap(Map<String, Object> data) {
        setFollowRedirects((boolean) data.get(FOLLOW_REDIRECTS_FIELD));
        setUser((User) data.get(USER_FIELD));
        setUseCookies((boolean) data.get(USE_COOKIES_FIELD));
        setUseGlobalState((boolean) data.get(USE_GLOBAL_STATE_FIELD));
        setMaxRedirects((int) data.get(MAX_REDIRECTS_FIELD));
        setMaxRetriesOnIoError((int) data.get(MAX_RETRIES_ON_IO_ERROR_FIELD));
        setRemoveUserDefinedAuthHeaders((boolean) data.get(REMOVE_USER_DEFINED_AUTH_HEADERS_FIELD));
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
