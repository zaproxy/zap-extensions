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
package org.zaproxy.addon.paramminer;

import java.nio.file.Path;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.users.User;

public class ParamMinerConfig {
    private String url;
    private boolean addFcbzCacheBuster;

    private boolean usePredefinedUrlWordlists;
    private boolean usePredefinedHeaderWordlists;
    private boolean usePredefinedCookieWordlists;

    private boolean useCustomUrlWordlists;
    private boolean useCustomHeaderWordlists;
    private boolean useCustomCookieWordlists;

    private boolean skipBoringHeaders;

    private int threadCount;
    private String context;
    private HttpRequestHeader presetHeaders;
    private int totalcustomParams;
    private int totalUrlParams;
    private int totalCookieParams;
    private int totalHeaderParams;
    private User scanUser;

    private boolean doUrlGuess;
    private boolean urlRedirect;
    private boolean doCookieGuess;
    private boolean cookieRedirect;
    private boolean doHeaderGuess;
    private boolean headerRedirect;
    private String customUrlWordListPath;

    private boolean urlXmlRequest;
    private String urlXmlIncludeString;
    private boolean urlJsonRequest;
    private String urlJsonIncludeString;
    private boolean urlPostRequest;
    private boolean urlGetRequest;

    public ParamMinerConfig() {
        this.url = "";
        this.addFcbzCacheBuster = false;
        /** This would allow user to use separate wordlists. */
        this.usePredefinedUrlWordlists = true;
        this.usePredefinedHeaderWordlists = true;
        this.usePredefinedCookieWordlists = true;

        this.useCustomUrlWordlists = false;
        this.useCustomHeaderWordlists = false;
        this.useCustomCookieWordlists = false;

        this.skipBoringHeaders = false;
        this.threadCount = 4;

        this.doUrlGuess = true;
        this.urlGetRequest = true;
        this.doCookieGuess = false;
        this.doHeaderGuess = false;
    }

    public String getUrl() {
        return this.url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public boolean getAddFcbzCacheBuster() {
        return addFcbzCacheBuster;
    }

    public void setAddFcbzCacheBuster(boolean addFcbzCacheBuster) {
        this.addFcbzCacheBuster = addFcbzCacheBuster;
    }

    public boolean getUsePredefinedUrlWordlists() {
        return usePredefinedUrlWordlists;
    }

    public void setUsePredefinedUrlWordlists(boolean usePredefinedUrlWordlists) {
        this.usePredefinedUrlWordlists = usePredefinedUrlWordlists;
    }

    public boolean getUsePredefinedHeaderWordlists() {
        return usePredefinedHeaderWordlists;
    }

    public void setUsePredefinedHeaderWordlists(boolean usePredefinedHeaderWordlists) {
        this.usePredefinedHeaderWordlists = usePredefinedHeaderWordlists;
    }

    public boolean getUsePredefinedCookieWordlists() {
        return usePredefinedCookieWordlists;
    }

    public void setUsePredefinedCookieWordlists(boolean usePredefinedCookieWordlists) {
        this.usePredefinedCookieWordlists = usePredefinedCookieWordlists;
    }

    public boolean getUseCustomUrlWordlists() {
        return useCustomUrlWordlists;
    }

    public void setUseCustomUrlWordlists(boolean useCustomUrlWordlists) {
        this.useCustomUrlWordlists = useCustomUrlWordlists;
    }

    public boolean getUseCustomHeaderWordlists() {
        return useCustomHeaderWordlists;
    }

    public void setUseCustomHeaderWordlists(boolean useCustomHeaderWordlists) {
        this.useCustomHeaderWordlists = useCustomHeaderWordlists;
    }

    public boolean getUseCustomCookieWordlists() {
        return useCustomCookieWordlists;
    }

    public void setUseCustomCookieWordlists(boolean useCustomCookieWordlists) {
        this.useCustomCookieWordlists = useCustomCookieWordlists;
    }

    public boolean doUrlGuess() {
        return doUrlGuess;
    }

    public void setDoUrlGuess(boolean doUrlGuess) {
        this.doUrlGuess = doUrlGuess;
    }

    public boolean doCookieGuess() {
        return doCookieGuess;
    }

    public void setDoCookieGuess(boolean doCookieGuess) {
        this.doCookieGuess = doCookieGuess;
    }

    public boolean doHeaderGuess() {
        return doHeaderGuess;
    }

    public void setDoHeaderGuess(boolean doHeaderGuess) {
        this.doHeaderGuess = doHeaderGuess;
    }

    public boolean getSkipBoringHeaders() {
        return skipBoringHeaders;
    }

    public void setSkipBoringHeaders(boolean skipBoringHeaders) {
        this.skipBoringHeaders = skipBoringHeaders;
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(String string) {
        threadCount = Integer.parseInt(string);
    }

    public String getContext() {
        return this.context;
    }

    public void setContext(String stringValue) {
        this.context = stringValue;
    }

    public boolean getUrlGuessRedirectState() {
        return urlRedirect;
    }

    public void setUrlGuessRedirectState(boolean bool) {
        this.urlRedirect = bool;
    }

    public boolean getCookieGuessRedirectState() {
        return cookieRedirect;
    }

    public void setCookieGuessRedirectState(boolean bool) {
        this.cookieRedirect = bool;
    }

    public boolean getHeaderGuessRedirectState() {
        return headerRedirect;
    }

    public void setHeaderGuessRedirectState(boolean bool) {
        this.headerRedirect = bool;
    }

    public HttpRequestHeader getPresetHeaders() {
        return presetHeaders;
    }

    public void setPresetHeaders(HttpRequestHeader presetHeaders) {
        this.presetHeaders = presetHeaders;
    }

    public int getTotalParams() {
        return totalcustomParams + totalUrlParams + totalCookieParams + totalHeaderParams;
    }

    public int setTotalUrlParams(int totalUrlParams) {
        return this.totalUrlParams = totalUrlParams;
    }

    public int getTotalUrlParams() {
        return totalUrlParams;
    }

    public int setTotalCookieParams(int totalCookieParams) {
        return this.totalCookieParams = totalCookieParams;
    }

    public int getTotalCookieParams() {
        return totalCookieParams;
    }

    public int setTotalHeaderParams(int totalHeaderParams) {
        return this.totalHeaderParams = totalHeaderParams;
    }

    public int getTotalHeaderParams() {
        return totalHeaderParams;
    }

    public User getScanUser() {
        return scanUser;
    }

    public void setScanUser(User scanUser) {
        this.scanUser = scanUser;
    }

    public String getCustomUrlWordlistPath() {
        return this.customUrlWordListPath;
    }

    public void setCustomUrlWordlistPath(Path path) {
        this.customUrlWordListPath = path.toString();
    }

    public void setCustomUrlWordlistPath(String string) {
        this.customUrlWordListPath = string;
    }

    public void setUrlJsonRequest(boolean urlJsonRequest) {
        this.urlJsonRequest = urlJsonRequest;
    }

    public boolean getUrlJsonRequest() {
        return urlJsonRequest;
    }

    public void setUrlJsonIncludeString(String urlJsonIncludeString) {
        this.urlJsonIncludeString = urlJsonIncludeString;
    }

    public String getUrlJsonIncludeString() {
        return urlJsonIncludeString;
    }

    public void setUrlXmlRequest(boolean urlXmlRequest) {
        this.urlXmlRequest = urlXmlRequest;
    }

    public boolean getUrlXmlRequest() {
        return urlXmlRequest;
    }

    public void setUrlXmlIncludeString(String urlXmlIncludeString) {
        this.urlXmlIncludeString = urlXmlIncludeString;
    }

    public String getUrlXmlIncludeString() {
        return urlXmlIncludeString;
    }

    public void setUrlPostRequest(boolean urlPostRequest) {
        this.urlPostRequest = urlPostRequest;
    }

    public boolean getUrlPostRequest() {
        return urlPostRequest;
    }

    public void setUrlGetRequest(boolean urlGetRequest) {
        this.urlGetRequest = urlGetRequest;
    }

    public boolean getUrlGetRequest() {
        return urlGetRequest;
    }
}
