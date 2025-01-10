/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;

/**
 * A provider of values.
 *
 * @since 1.29.0
 * @see ExtensionCommonlib#getValueProvider()
 */
public interface ValueProvider {

    /**
     * Gets a value for the given field name.
     *
     * @param uri the uri
     * @param url the resolved URL
     * @param fieldId the name associated with the current field
     * @param defaultValue the value of 'value attribute' if it has one
     * @param definedValues the predefined values for the field, if present
     * @param envAttributes all attributes of the current form
     * @param fieldAttributes all attributes of the current field
     */
    String getValue(
            URI uri,
            String url,
            String fieldId,
            String defaultValue,
            List<String> definedValues,
            Map<String, String> envAttributes,
            Map<String, String> fieldAttributes);
}
