/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt.ui;

import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler.FileStringPayloadGeneratorUI;

/**
 * This class {@code CustomFieldFuzzer} is used for storing values of custom fields under general
 * settings section in UI.
 *
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 */
public class CustomFieldFuzzer {

    /** JSON Field Name in Header or Payload eg. Kid header field */
    private String fieldName;

    /** fieldName is present in Header or Payload */
    private boolean isHeaderField = true;

    private boolean isSignatureRequired;

    private String signingKey;

    private FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI;

    public String getFieldName() {
        return fieldName;
    }

    public void setFieldName(String fieldName) {
        this.fieldName = fieldName;
    }

    public boolean isHeaderField() {
        return isHeaderField;
    }

    public void setHeaderField(boolean isHeaderField) {
        this.isHeaderField = isHeaderField;
    }

    public boolean isSignatureRequired() {
        return isSignatureRequired;
    }

    public void setSignatureRequired(boolean isSignatureRequired) {
        this.isSignatureRequired = isSignatureRequired;
    }

    public FileStringPayloadGeneratorUI getFileStringPayloadGeneratorUI() {
        return fileStringPayloadGeneratorUI;
    }

    public void setFileStringPayloadGeneratorUI(
            FileStringPayloadGeneratorUI fileStringPayloadGeneratorUI) {
        this.fileStringPayloadGeneratorUI = fileStringPayloadGeneratorUI;
    }

    public String getSigningKey() {
        return signingKey;
    }

    public void setSigningKey(String signingKey) {
        this.signingKey = signingKey;
    }
}
