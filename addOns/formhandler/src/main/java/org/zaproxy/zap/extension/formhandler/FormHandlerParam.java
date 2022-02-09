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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.apache.commons.configuration.ConversionException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;

public class FormHandlerParam extends AbstractParam {

    private static final Logger logger = LogManager.getLogger(FormHandlerParam.class);

    private static final String FORM_HANDLER_BASE_KEY = "formhandler";

    private static final String ALL_TOKENS_KEY = FORM_HANDLER_BASE_KEY + ".fields.field";

    private static final String TOKEN_NAME_KEY = "fieldId";
    private static final String TOKEN_VALUE_KEY = "value";
    private static final String TOKEN_ENABLED_KEY = "enabled";
    private static final String CONFIRM_REMOVE_TOKEN_KEY =
            FORM_HANDLER_BASE_KEY + ".confirmRemoveField";

    private List<FormHandlerParamField> fields = null;
    private List<String> enabledFieldsNames = null;

    private boolean confirmRemoveField = true;

    private static final Map<String, String> DEFAULT_KEY_VALUE_PAIRS = new HashMap<>();

    static {
        DEFAULT_KEY_VALUE_PAIRS.put("color", "#ffffff");
        DEFAULT_KEY_VALUE_PAIRS.put("email", "foo-bar@example.com");
        DEFAULT_KEY_VALUE_PAIRS.put("name", "ZAP");
        DEFAULT_KEY_VALUE_PAIRS.put("password", "ZAP");
        DEFAULT_KEY_VALUE_PAIRS.put("phone", "9999999999");
        DEFAULT_KEY_VALUE_PAIRS.put("url", "https://www.example.com");
    }

    @Override
    protected void parse() {
        try {
            List<HierarchicalConfiguration> fields =
                    ((HierarchicalConfiguration) getConfig()).configurationsAt(ALL_TOKENS_KEY);
            this.fields = new ArrayList<>(fields.size());
            enabledFieldsNames = new ArrayList<>(fields.size());
            List<String> tempFieldsNames = new ArrayList<>(fields.size());
            for (HierarchicalConfiguration sub : fields) {
                String value = sub.getString(TOKEN_VALUE_KEY, "");
                String name = sub.getString(TOKEN_NAME_KEY, "");
                if (!"".equals(name) && !tempFieldsNames.contains(name)) {
                    boolean enabled = sub.getBoolean(TOKEN_ENABLED_KEY, true);
                    this.fields.add(new FormHandlerParamField(name, value, enabled));
                    tempFieldsNames.add(name);
                    if (enabled) {
                        enabledFieldsNames.add(name);
                    }
                }
            }
        } catch (ConversionException e) {
            logger.error("Error while loading key-value pair fields: {}", e.getMessage(), e);
            this.fields = new ArrayList<>(DEFAULT_KEY_VALUE_PAIRS.size());
            this.enabledFieldsNames = new ArrayList<>(DEFAULT_KEY_VALUE_PAIRS.size());
        }

        if (this.fields.isEmpty()) {
            // Grab the entry for every set in the map
            for (Map.Entry<String, String> entry : DEFAULT_KEY_VALUE_PAIRS.entrySet()) {
                // Store the key and value of that entry in variables
                String name = entry.getKey();
                String value = entry.getValue();
                this.fields.add(new FormHandlerParamField(name, value));
                this.enabledFieldsNames.add(name);
            }
        }

        this.confirmRemoveField = getBoolean(CONFIRM_REMOVE_TOKEN_KEY, true);
    }

    @ZapApiIgnore
    public List<FormHandlerParamField> getFields() {
        return fields;
    }

    @ZapApiIgnore
    public void setFields(List<FormHandlerParamField> fields) {
        this.fields = new ArrayList<>(fields);

        ((HierarchicalConfiguration) getConfig()).clearTree(ALL_TOKENS_KEY);

        ArrayList<String> enabledFields = new ArrayList<>(fields.size());
        for (int i = 0, size = fields.size(); i < size; ++i) {
            String elementBaseKey = ALL_TOKENS_KEY + "(" + i + ").";
            FormHandlerParamField field = fields.get(i);

            getConfig().setProperty(elementBaseKey + TOKEN_NAME_KEY, field.getName().toLowerCase());
            getConfig().setProperty(elementBaseKey + TOKEN_VALUE_KEY, field.getValue());
            getConfig()
                    .setProperty(
                            elementBaseKey + TOKEN_ENABLED_KEY, Boolean.valueOf(field.isEnabled()));

            if (field.isEnabled()) {
                enabledFields.add(field.getName().toLowerCase());
            }
        }

        enabledFields.trimToSize();
        this.enabledFieldsNames = enabledFields;
    }

    /**
     * Adds a new field with the given {@code name} and {@code value}, enabled by default.
     *
     * <p>The call to this method has no effect if the given {@code name} is null or empty, or a
     * field with the given name already exist.
     *
     * @param name the name of the field that will be added
     * @param value the value of the field that will be added
     */
    public void addField(String name, String value) {
        if (name == null || name.isEmpty()) {
            return;
        }

        for (Iterator<FormHandlerParamField> it = fields.iterator(); it.hasNext(); ) {
            if (name.equalsIgnoreCase(it.next().getName())) {
                return;
            }
        }

        this.fields.add(new FormHandlerParamField(name, value));

        this.enabledFieldsNames.add(name);
    }

    /**
     * Removes the field with the given {@code name}.
     *
     * <p>The call to this method has no effect if the given {@code name} is null or empty, or a
     * field with the given {@code name} does not exist.
     *
     * @param name the name of the field that will be removed
     */
    public void removeField(String name) {
        if (name == null || name.isEmpty()) {
            return;
        }

        for (Iterator<FormHandlerParamField> it = fields.iterator(); it.hasNext(); ) {
            FormHandlerParamField field = it.next();
            if (name.equalsIgnoreCase(field.getName())) {
                it.remove();
                if (field.isEnabled()) {
                    this.enabledFieldsNames.remove(name);
                }
                break;
            }
        }
    }

    /**
     * Gets the value for the field {@code name} by searching through all existing fields
     *
     * @param name the name of the field being queried.
     * @return the value of the field
     */
    public String getField(String name) {
        for (FormHandlerParamField field : fields) {
            if (field.getName().equalsIgnoreCase(name)) {
                return field.getValue();
            }
        }
        return null;
    }

    public List<String> getEnabledFieldsNames() {
        return enabledFieldsNames;
    }

    /**
     * Gets the value of the field that is enabled and matches {@code name}. If the field exists in
     * the current list then it will return its value
     *
     * @param name the name of the field that is being checked
     * @return string of the enabled field's value
     */
    public String getEnabledFieldValue(String name) {
        for (FormHandlerParamField field : fields) {
            if (field.getName().equalsIgnoreCase(name) && field.isEnabled()) {
                String value = field.getValue();
                return value;
            }
        }
        return null;
    }

    @ZapApiIgnore
    public boolean isConfirmRemoveField() {
        return this.confirmRemoveField;
    }

    @ZapApiIgnore
    public void setConfirmRemoveField(boolean confirmRemove) {
        this.confirmRemoveField = confirmRemove;
        getConfig().setProperty(CONFIRM_REMOVE_TOKEN_KEY, Boolean.valueOf(confirmRemoveField));
    }
}
