/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.parosproxy.paros.network.HttpHeader;
import org.zaproxy.zap.extension.httpsessions.ExtensionHttpSessions;

/**
 * The HttpSessionsParam is used to store the parameters (options) for the {@link
 * ExtensionHttpSessions} and related classes.
 */
public class ZestParam extends AbstractParam {

    /** The Constant defining the key for the default session tokens used in the application. */
    private static final String DEFAULT_ZEST_KEY = "zest";

    /** The full list of headers that can be ignored. */
    private static final String[] ALL_HEADERS = {
        "Accept",
        HttpHeader.ACCEPT_ENCODING,
        "Accept-Language",
        HttpHeader.AUTHORIZATION,
        HttpHeader.CACHE_CONTROL,
        HttpHeader.CONNECTION,
        HttpHeader.CONTENT_ENCODING,
        HttpHeader.CONTENT_LENGTH,
        HttpHeader.CONTENT_TYPE,
        HttpHeader.COOKIE,
        "Host",
        HttpHeader.IF_MODIFIED_SINCE,
        HttpHeader.IF_NONE_MATCH,
        HttpHeader.LOCATION,
        HttpHeader.PRAGMA,
        HttpHeader.PROXY_AUTHENTICATE,
        HttpHeader.REFERER,
        HttpHeader.SET_COOKIE,
        HttpHeader.SET_COOKIE2,
        HttpHeader.USER_AGENT,
        HttpHeader.WWW_AUTHENTICATE,
    };

    private static final String[] DEFAULT_IGNORED_HEADERS = {
        "Accept",
        HttpHeader.ACCEPT_ENCODING,
        "Accept-Language",
        HttpHeader.CACHE_CONTROL,
        HttpHeader.CONNECTION,
        HttpHeader.COOKIE,
        "Host",
        HttpHeader.IF_MODIFIED_SINCE,
        HttpHeader.IF_NONE_MATCH,
        HttpHeader.LOCATION,
        HttpHeader.PRAGMA,
        HttpHeader.REFERER,
        HttpHeader.SET_COOKIE,
        HttpHeader.SET_COOKIE2,
        HttpHeader.USER_AGENT,
    };

    private static final String IGNORE_HEADERS_KEY = DEFAULT_ZEST_KEY + ".ignoreHeaders";
    private static final String INCLUDE_RESPONSES_KEY = DEFAULT_ZEST_KEY + ".incResponses";

    /** The Constant log. */
    private static final Logger log = LogManager.getLogger(ZestParam.class);

    /** The full list of headers that can be ignored. */
    private List<String> allHeaders = new ArrayList<>();

    /** The list of headers that will be ignored. */
    private List<String> ignoredHeaders = new ArrayList<>();

    private boolean includeResponses = true;

    /** Instantiates a new Zest param. */
    public ZestParam() {}

    @Override
    protected void parse() {
        this.includeResponses = getBoolean(INCLUDE_RESPONSES_KEY, true);
        try {

            this.allHeaders.clear();
            for (String header : ALL_HEADERS) {
                this.allHeaders.add(header);
            }

            this.ignoredHeaders.clear();
            List<Object> ignoreList = getConfig().getList(IGNORE_HEADERS_KEY);
            if (ignoreList == null || ignoreList.isEmpty()) {
                // Use the defaults
                for (String header : DEFAULT_IGNORED_HEADERS) {
                    this.ignoredHeaders.add(header);
                }
            } else {
                for (Object header : ignoreList) {
                    this.ignoredHeaders.add(header.toString());
                }
            }

        } catch (ConversionException e) {
            log.error("Error while parsing config file: {}", e.getMessage(), e);
            // Use the defaults
            for (String header : DEFAULT_IGNORED_HEADERS) {
                this.ignoredHeaders.add(header);
            }
        }
    }

    public final List<String> getAllHeaders() {
        return Collections.unmodifiableList(allHeaders);
    }

    public final List<String> getIgnoredHeaders() {
        return Collections.unmodifiableList(this.ignoredHeaders);
    }

    /**
     * Sets the ignored headers.
     *
     * @param ignoredHeaders the ignored Headers
     */
    public void setIgnoredHeaders(final List<String> ignoredHeaders) {
        this.ignoredHeaders = new ArrayList<>(ignoredHeaders);
        getConfig().setProperty(IGNORE_HEADERS_KEY, this.ignoredHeaders);
    }

    public boolean isIncludeResponses() {
        return includeResponses;
    }

    public void setIncludeResponses(boolean includeResponses) {
        this.includeResponses = includeResponses;
        getConfig().setProperty(INCLUDE_RESPONSES_KEY, this.includeResponses);
    }
}
