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

import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateDecoder;

import java.util.regex.Matcher;

public class ViewState extends Base64Data {

    private final boolean validViewState;
    private final String viewStateXml;
    private final boolean isViewStateNotProtectedByMAC;

    public ViewState(String originalData, String transformData, byte[] decodedData)
            throws Exception {
        super(originalData, transformData, decodedData);
        this.viewStateXml = ViewStateDecoder.decodeAsXML(decodedData);
        this.validViewState = true;
        isViewStateNotProtectedByMAC = isViewStateProtectedByMAC();
    }

    public static ViewState from(Base64Data base64Data) throws Exception {
        return new ViewState(
                base64Data.originalData, base64Data.transformData, base64Data.decodedData);
    }

    public boolean isValidViewState() {
        return validViewState;
    }

    public String getViewStateXml() {
        return viewStateXml;
    }

    public boolean isViewStateNotProtectedByMAC() {
        return isViewStateNotProtectedByMAC;
    }

    private boolean isViewStateProtectedByMAC() {
        boolean macless;
        Matcher hmaclessmatcher = ViewStateByteReader.hasNoHMac(viewStateXml);
        macless = hmaclessmatcher.find();
        return macless;
    }
}
