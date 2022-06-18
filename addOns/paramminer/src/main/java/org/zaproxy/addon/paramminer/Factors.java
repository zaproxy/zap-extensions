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

import java.util.List;
import org.parosproxy.paros.network.HttpHeaderField;

public class Factors {
    private boolean sameCode;
    private boolean sameBody;
    private boolean samePlainText;
    private boolean sameHeaders;
    private boolean sameRedirect;
    private boolean linesNum;
    private boolean linesDiff;
    private boolean paramMissing;
    private boolean valueMissing;

    private List<HttpHeaderField> headers;
    private long linesNumValue;
    private String plainText;
    private List<String> diffMapLines;
    private String sameRedirectPath;
    private List<String> missingParams;

    Factors() {
        sameCode = false;
        sameBody = false;
        samePlainText = false;
        sameHeaders = false;
        sameRedirect = false;
        linesNum = false;
        linesDiff = false;
        paramMissing = false;
        valueMissing = false;
    }

    public boolean isSameCode() {
        return sameCode;
    }

    public void setSameCode(boolean sameCode) {
        this.sameCode = sameCode;
    }

    public boolean isSameBody() {
        return sameBody;
    }

    public void setSameBody(boolean sameBody) {
        this.sameBody = sameBody;
    }

    public boolean isSamePlainText() {
        return samePlainText;
    }

    public void setSamePlainText(boolean samePlainText) {
        this.samePlainText = samePlainText;
    }

    public boolean isSameHeaders() {
        return sameHeaders;
    }

    public void setSameHeaders(boolean sameHeaders) {
        this.sameHeaders = sameHeaders;
    }

    public boolean isSameRedirect() {
        return sameRedirect;
    }

    public void setSameRedirect(boolean sameRedirect) {
        this.sameRedirect = sameRedirect;
    }

    public boolean isLinesNum() {
        return linesNum;
    }

    public void setLinesNum(boolean linesNum) {
        this.linesNum = linesNum;
    }

    public boolean isLinesDiff() {
        return linesDiff;
    }

    public void setLinesDiff(boolean linesDiff) {
        this.linesDiff = linesDiff;
    }

    public boolean isParamMissing() {
        return paramMissing;
    }

    public void setParamMissing(boolean paramMissing) {
        this.paramMissing = paramMissing;
    }

    public boolean isValueMissing() {
        return valueMissing;
    }

    public void setValueMissing(boolean valueMissing) {
        this.valueMissing = valueMissing;
    }

    public List<HttpHeaderField> getHeaders() {
        return headers;
    }

    public void setHeaders(List<HttpHeaderField> headers) {
        setSameHeaders(true);
        this.headers = headers;
    }

    public long getLinesNumValue() {
        return linesNumValue;
    }

    public void setLinesNumValue(long linesNumValue) {
        setLinesNum(true);
        this.linesNumValue = linesNumValue;
    }

    public String getPlainText() {
        return plainText;
    }

    public void setPlainText(String plainText) {
        setSamePlainText(true);
        this.plainText = plainText;
    }

    public List<String> getDiffMapLines() {
        return diffMapLines;
    }

    public void setDiffMapLines(List<String> diffMapLines) {
        setLinesDiff(true);
        this.diffMapLines = diffMapLines;
    }

    public String getSameRedirectPath() {
        return sameRedirectPath;
    }

    public void setSameRedirectPath(String sameRedirectPath) {
        setSameRedirect(true);
        this.sameRedirectPath = sameRedirectPath;
    }

    public List<String> getMissingParams() {
        return missingParams;
    }

    public void setMissingParams(List<String> missingParams) {
        setParamMissing(true);
        this.missingParams = missingParams;
    }
}
