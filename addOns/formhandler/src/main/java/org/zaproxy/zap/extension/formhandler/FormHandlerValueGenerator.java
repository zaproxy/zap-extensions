/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;

public class FormHandlerValueGenerator implements ValueGenerator {

    private FormHandlerParam param;

    private DefaultValueGenerator defaultValueGenerator = new DefaultValueGenerator();

    public FormHandlerValueGenerator(FormHandlerParam param) {
        this.param = param;
    }

    @Override
    public String getValue(
            URI uri,
            String url,
            String fieldId,
            String defaultValue,
            List<String> definedValues,
            Map<String, String> envAttributes,
            Map<String, String> fieldAttributes) {

        if (fieldId == null || fieldId.isEmpty()) {
            return defaultValue != null ? defaultValue : "";
        }

        // Check to see if there is an enabled field for the current field being processed, based on
        // field attribute 'name'
        String value = param.getEnabledFieldValue(fieldId.toLowerCase());

        // If there is an existing field in the list
        if (value != null) {
            return value;
        }

        // In all other cases pass the field to the defaultValueGenerator
        return defaultValueGenerator.getValue(
                uri, url, fieldId, defaultValue, definedValues, envAttributes, fieldAttributes);
    }
}
