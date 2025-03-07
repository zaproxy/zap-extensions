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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;

/**
 * Default implementation of the {@link ValueProvider}.
 *
 * <p>Generally it should not be used directly it should be used the one from {@link
 * ExtensionCommonlib#getValueProvider()}.
 *
 * @since 1.29.0
 */
public class DefaultValueProvider implements ValueProvider {

    static final String CONTROL_TYPE_ATTRIBUTE = "Control Type";

    private static final String ATTR_TYPE = "type";
    private static final String DEFAULT_NUMBER_VALUE = "1";
    static final String DEFAULT_TEXT_VALUE = org.parosproxy.paros.Constant.PROGRAM_NAME_SHORT;
    static final String DEFAULT_PASS_VALUE = DEFAULT_TEXT_VALUE;
    static final String DEFAULT_FILE_VALUE = "test_file.txt";
    static final String DEFAULT_EMPTY_VALUE = "";

    private Date defaultDate;

    /**
     * Gets the default {@code Date}, to be used for default values of date fields.
     *
     * @return the date, never {@code null}.
     * @see #setDefaultDate(Date)
     */
    public Date getDefaultDate() {
        if (defaultDate == null) {
            return new Date();
        }
        return defaultDate;
    }

    public void setDefaultDate(Date date) {
        this.defaultDate = date;
    }

    /**
     * Generates accurate field values for following types:
     *
     * <ul>
     *   <li>Text/Password/Search - DEFAULT_TEXT_VALUE
     *   <li>number/range - if min is defined, then use min. If max is defined use max, otherwise
     *       DEFAULT_NUMBER_VALUE
     *   <li>url - http://www.example.com
     *   <li>email - foo-bar@example.com
     *   <li>color - #ffffff
     *   <li>tel - 9999999999
     *   <li>date/datetime/time/month/week/datetime-local - current date in the proper format
     *   <li>file - DEFAULT_FILE_VALUE
     * </ul>
     *
     * @return the default String value for each control type
     */
    @Override
    public String getValue(
            URI uri,
            String url,
            String fieldId,
            String defaultValue,
            List<String> definedValues,
            Map<String, String> envAttributes,
            Map<String, String> fieldAttributes) {

        if (StringUtils.isNotEmpty(defaultValue)) {
            return defaultValue;
        }

        if (fieldAttributes == null) {
            return DEFAULT_EMPTY_VALUE;
        }

        String controlType = fieldAttributes.get(CONTROL_TYPE_ATTRIBUTE);
        if ("TEXT".equalsIgnoreCase(controlType)) {
            // Converted FormControlType to String to allow for case insensitive comparison
            // If the control type was reduced to a TEXT type by the Jericho library, check the
            // HTML5 type and use proper values
            String type = fieldAttributes.get(ATTR_TYPE);
            if (type == null || type.equalsIgnoreCase("text")) {
                return DEFAULT_TEXT_VALUE;
            }
            if (type.equalsIgnoreCase("number") || type.equalsIgnoreCase("range")) {
                String min = fieldAttributes.get("min");
                if (min != null) {
                    return min;
                }
                String max = fieldAttributes.get("max");
                if (max != null) {
                    return max;
                }
                return DEFAULT_NUMBER_VALUE;
            }
            if (type.equalsIgnoreCase("url")) {
                return "http://www.example.com";
            }
            if (type.equalsIgnoreCase("email")) {
                return "foo-bar@example.com";
            }
            if (type.equalsIgnoreCase("color")) {
                return "#ffffff";
            }
            if (type.equalsIgnoreCase("tel")) {
                return "9999999999";
            }
            if (type.equalsIgnoreCase("datetime")) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
                return format.format(getDefaultDate());
            }
            if (type.equalsIgnoreCase("datetime-local")) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
                return format.format(getDefaultDate());
            }
            if (type.equalsIgnoreCase("date")) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
                return format.format(getDefaultDate());
            }
            if (type.equalsIgnoreCase("time")) {
                SimpleDateFormat format = new SimpleDateFormat("HH:mm:ss");
                return format.format(getDefaultDate());
            }
            if (type.equalsIgnoreCase("month")) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-MM");
                return format.format(getDefaultDate());
            }
            if (type.equalsIgnoreCase("week")) {
                SimpleDateFormat format = new SimpleDateFormat("yyyy-'W'ww");
                return format.format(getDefaultDate());
            }
        } else if ("PASSWORD".equalsIgnoreCase(controlType)) {
            return DEFAULT_PASS_VALUE;
        } else if ("FILE".equalsIgnoreCase(controlType)) {
            return DEFAULT_FILE_VALUE;
        }
        return DEFAULT_EMPTY_VALUE;
    }
}
