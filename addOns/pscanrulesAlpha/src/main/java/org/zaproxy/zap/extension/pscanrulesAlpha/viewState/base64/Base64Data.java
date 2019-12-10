/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState.base64;

public class Base64Data {
    public final String originalData;
    public final String transformData;
    public final byte[] decodedData;

    public Base64Data(String originalData, String transformData, byte[] decodedData) {
        this.originalData = originalData;
        this.transformData = transformData;
        this.decodedData = decodedData;
    }

    /**
     * Try to
     *
     * @return a possible ViewState if it is recognized
     */
    public Base64Data validateViewState() {
        // so it's valid Base64.  Is it valid .NET ViewState data?
        // This will be true for both __VIEWSTATE and __EVENTVALIDATION data, although
        // currently, we can only interpret/decode __VIEWSTATE.

        if (decodedData[0] != -1 && decodedData[1] != 0x01) {
            return this;
        }
        // TODO: decode __EVENTVALIDATION data
        try {
            return ViewState.from(this);
        } catch (Exception e) {
            return this;
        }
    }

    public boolean isValidViewState() {
        return false;
    }

    public String getViewStateXml() {
        throw new IllegalStateException("Object is not a valid ViewState");
    }

    public boolean isViewStateNotProtectedByMAC() {
        throw new IllegalStateException("Object is not a valid ViewState");
    }
}
