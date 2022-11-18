/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

public class SarifMessage {
    private String text;

    public static class SarifMessageBuilder {
        private SarifHtmlToPlainTextConverter converter = SarifHtmlToPlainTextConverter.DEFAULT;
        private String plainText;

        public SarifMessageBuilder setContentAsHtml(String html) {
            this.plainText = converter.convertToPlainText(html);
            return this;
        }

        public SarifMessageBuilder setContentAsPlainText(String plainText) {
            this.plainText = plainText;
            return this;
        }

        SarifMessageBuilder setConverter(SarifHtmlToPlainTextConverter converter) {
            this.converter = converter;
            return this;
        }

        public SarifMessage build() {
            SarifMessage message = new SarifMessage();
            message.text = plainText;
            return message;
        }
    }

    public static SarifMessageBuilder builder() {
        return new SarifMessageBuilder();
    }

    private SarifMessage() {
        // force usage of builder
    }

    public String getText() {
        return text;
    }
}
