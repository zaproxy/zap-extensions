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
package org.zaproxy.addon.paramdigger;

public class Cache {
    private boolean cacheBusterFound;
    private boolean cacheBusterIsParameter;
    private boolean cacheBusterIsHeader;
    private boolean cacheBusterIsCookie;
    private boolean cacheBusterIsHttpMethod;
    private String cacheBusterName;

    private boolean noCache;
    private String indicator;
    private boolean timeIndicator;

    public Cache() {
        cacheBusterName = "";
        indicator = "";
    }

    public boolean isCacheBusterFound() {
        return cacheBusterFound;
    }

    public void setCacheBusterFound(boolean cacheBusterFound) {
        this.cacheBusterFound = cacheBusterFound;
    }

    public boolean isCacheBusterIsParameter() {
        return cacheBusterIsParameter;
    }

    public void setCacheBusterIsParameter(boolean cacheBusterIsParameter) {
        this.cacheBusterIsParameter = cacheBusterIsParameter;
    }

    public boolean isCacheBusterIsHeader() {
        return cacheBusterIsHeader;
    }

    public void setCacheBusterIsHeader(boolean cacheBusterIsHeader) {
        this.cacheBusterIsHeader = cacheBusterIsHeader;
    }

    public boolean isCacheBusterIsCookie() {
        return cacheBusterIsCookie;
    }

    public void setCacheBusterIsCookie(boolean cacheBusterIsCookie) {
        this.cacheBusterIsCookie = cacheBusterIsCookie;
    }

    public boolean isCacheBusterIsHttpMethod() {
        return cacheBusterIsHttpMethod;
    }

    public void setCacheBusterIsHttpMethod(boolean cacheIsHttpMethod) {
        this.cacheBusterIsHttpMethod = cacheIsHttpMethod;
    }

    public String getCacheBusterName() {
        return cacheBusterName;
    }

    public void setCacheBusterName(String cacheBusterName) {
        this.cacheBusterName = cacheBusterName;
    }

    public boolean isNoCache() {
        return noCache;
    }

    public void setNoCache(boolean noCache) {
        this.noCache = noCache;
    }

    public String getIndicator() {
        return indicator;
    }

    public void setIndicator(String indicator) {
        this.indicator = indicator;
    }

    public boolean hasTimeIndicator() {
        return timeIndicator;
    }

    public void setTimeIndicator(boolean timeIndicator) {
        this.timeIndicator = timeIndicator;
    }
}
