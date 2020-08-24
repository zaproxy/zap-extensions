/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.dialogs;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.mozilla.zest.core.v1.ZestAssignCalc;
import org.mozilla.zest.core.v1.ZestAssignFieldValue;
import org.mozilla.zest.core.v1.ZestAssignFromElement;
import org.mozilla.zest.core.v1.ZestAssignGlobalVariable;
import org.mozilla.zest.core.v1.ZestAssignRandomInteger;
import org.mozilla.zest.core.v1.ZestAssignRegexDelimiters;
import org.mozilla.zest.core.v1.ZestAssignReplace;
import org.mozilla.zest.core.v1.ZestAssignString;
import org.mozilla.zest.core.v1.ZestAssignStringDelimiters;
import org.mozilla.zest.core.v1.ZestAssignment;
import org.mozilla.zest.core.v1.ZestFieldDefinition;
import org.mozilla.zest.core.v1.ZestRequest;
import org.mozilla.zest.core.v1.ZestStatement;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestAssignmentDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_VARIABLE = "zest.dialog.assign.label.variable";
    private static final String FIELD_MIN_INT = "zest.dialog.assign.label.minint";
    private static final String FIELD_MAX_INT = "zest.dialog.assign.label.maxint";
    private static final String FIELD_REPLACE_FORM = "zest.dialog.assign.label.repform";
    private static final String FIELD_REPLACE_FIELD = "zest.dialog.assign.label.repfield";
    private static final String FIELD_LOCATION = "zest.dialog.assign.label.location";
    private static final String FIELD_OPERAND_A = "zest.dialog.assign.label.operanda";
    private static final String FIELD_OPERAND_B = "zest.dialog.assign.label.operandb";
    private static final String FIELD_OPERATION = "zest.dialog.assign.label.operation";
    private static final String FIELD_REGEX = "zest.dialog.assign.label.regex";
    private static final String FIELD_EXACT = "zest.dialog.assign.label.exact";
    private static final String FIELD_REGEX_PREFIX = "zest.dialog.assign.label.rgxprefix";
    private static final String FIELD_REGEX_POSTFIX = "zest.dialog.assign.label.rgxpostfix";
    private static final String FIELD_REPLACE = "zest.dialog.assign.label.replace";
    private static final String FIELD_REPLACEMENT = "zest.dialog.assign.label.replacement";
    private static final String FIELD_STRING = "zest.dialog.assign.label.string";
    private static final String FIELD_STRING_PREFIX = "zest.dialog.assign.label.strprefix";
    private static final String FIELD_STRING_POSTFIX = "zest.dialog.assign.label.strpostfix";
    private static final String FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT =
            "zest.dialog.assign.label.filterByElement";
    private static final String FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME =
            "zest.dialog.assign.label.filterByElementName";
    private static final String FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE =
            "zest.dialog.assign.label.filterByAttribute";
    private static final String FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME =
            "zest.dialog.assign.label.filterByAttributeName";
    private static final String FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE =
            "zest.dialog.assign.label.filterByAttributeValue";
    private static final String FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_REVERSED =
            "zest.dialog.assign.label.filteredElementsReversed";
    private static final String FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX =
            "zest.dialog.assign.label.filteredElementsIndex";
    private static final String FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR =
            "zest.dialog.assign.label.filteredElementsSelector";
    private static final String FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME =
            "zest.dialog.assign.label.filteredElementsSelectorAttributeName";
    private static final String FROM_ELEMENT_SELECTOR_CONTENT = "Content";
    private static final String FROM_ELEMENT_SELECTOR_ATTRIBUTE = "Attribute";
    private static final String FIELD_GLOBAL_VAR = "zest.dialog.assign.label.globalvar";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ZestScriptWrapper script = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;
    private ZestStatement stmt = null;
    private ZestAssignment assign = null;
    private boolean add = false;

    public ZestAssignmentDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.assign.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestStatement stmt,
            ZestAssignment assign,
            boolean add) {
        this.add = add;
        this.script = script;
        this.parent = parent;
        this.child = child;
        this.stmt = stmt;
        this.assign = assign;

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.assign.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.assign.edit.title"));
        }

        if (assign instanceof ZestAssignFieldValue) {
            ZestAssignFieldValue za = (ZestAssignFieldValue) assign;
            if (za.getFieldDefinition() == null) {
                za.setFieldDefinition(new ZestFieldDefinition());
            }
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());
            this.addComboField(FIELD_REPLACE_FORM, new String[] {}, "");
            this.addFieldListener(
                    FIELD_REPLACE_FORM,
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            initFieldField(null);
                        }
                    });

            this.addComboField(FIELD_REPLACE_FIELD, new String[] {}, "");

            // Set default values
            initFormField(Integer.toString(za.getFieldDefinition().getFormIndex()));
            initFieldField(za.getFieldDefinition().getFieldName());

        } else if (assign instanceof ZestAssignRandomInteger) {
            ZestAssignRandomInteger za = (ZestAssignRandomInteger) assign;
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());
            this.addNumberField(FIELD_MIN_INT, 0, Integer.MAX_VALUE, za.getMinInt());
            this.addNumberField(FIELD_MAX_INT, 0, Integer.MAX_VALUE, za.getMaxInt());

        } else if (assign instanceof ZestAssignRegexDelimiters) {
            ZestAssignRegexDelimiters za = (ZestAssignRegexDelimiters) assign;
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());
            this.addComboField(FIELD_LOCATION, new String[] {"HEAD", "BODY"}, za.getLocation());
            this.addTextField(FIELD_REGEX_PREFIX, za.getPrefix());
            this.addTextField(FIELD_REGEX_POSTFIX, za.getPostfix());

        } else if (assign instanceof ZestAssignStringDelimiters) {
            ZestAssignStringDelimiters za = (ZestAssignStringDelimiters) assign;
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());
            this.addComboField(FIELD_LOCATION, new String[] {"HEAD", "BODY"}, za.getLocation());
            this.addTextField(FIELD_STRING_PREFIX, za.getPrefix());
            this.addTextField(FIELD_STRING_POSTFIX, za.getPostfix());

        } else if (assign instanceof ZestAssignString) {
            ZestAssignString za = (ZestAssignString) assign;
            this.addComboField(
                    FIELD_VARIABLE, this.getVariableNames(true), assign.getVariableName(), true);
            this.addTextField(FIELD_STRING, za.getString());

            setFieldMainPopupMenu(FIELD_STRING);

        } else if (assign instanceof ZestAssignReplace) {
            ZestAssignReplace za = (ZestAssignReplace) assign;
            this.addComboField(
                    FIELD_VARIABLE, this.getVariableNames(false), assign.getVariableName(), false);
            this.addTextField(FIELD_REPLACE, za.getReplace());
            this.addTextField(FIELD_REPLACEMENT, za.getReplacement());
            this.addCheckBoxField(FIELD_REGEX, za.isRegex());
            this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());

            setFieldMainPopupMenu(FIELD_REPLACE);
            setFieldMainPopupMenu(FIELD_REPLACEMENT);

        } else if (assign instanceof ZestAssignCalc) {
            ZestAssignCalc za = (ZestAssignCalc) assign;
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());
            this.addTextField(FIELD_OPERAND_A, za.getOperandA());
            this.addTextField(FIELD_OPERAND_B, za.getOperandB());
            this.addComboField(
                    FIELD_OPERATION,
                    new String[] {
                        Constant.messages.getString("zest.dialog.assign.oper.add"),
                        Constant.messages.getString("zest.dialog.assign.oper.subtract"),
                        Constant.messages.getString("zest.dialog.assign.oper.multiply"),
                        Constant.messages.getString("zest.dialog.assign.oper.divide")
                    },
                    ZestZapUtils.calcOperationToLabel(za.getOperation()));

            setFieldMainPopupMenu(FIELD_STRING);

        } else if (assign instanceof ZestAssignFromElement) {
            ZestAssignFromElement za = (ZestAssignFromElement) assign;
            this.setSize(new Dimension(600, 450));
            this.addTextField(FIELD_VARIABLE, assign.getVariableName());

            this.addCheckBoxField(
                    FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT, za.isFilteredByElementName());
            this.addTextField(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME, za.getElementNameFilter());
            this.addFieldListenerToSetEnabledOnCheckedChanged(
                    FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT,
                    new String[] {FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME});

            this.addCheckBoxField(
                    FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE, za.isFilteredByAttribute());
            this.addTextField(
                    FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME, za.getAttributeNameFilter());
            this.addTextField(
                    FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE, za.getAttributeValueFilter());
            this.addFieldListenerToSetEnabledOnCheckedChanged(
                    FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE,
                    new String[] {
                        FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME,
                        FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE
                    });

            this.addCheckBoxField(
                    FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_REVERSED,
                    za.areFilteredElementsReversed());
            this.addNumberField(
                    FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX,
                    0,
                    Integer.MAX_VALUE,
                    za.getElementIndex());

            this.addComboField(
                    FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR,
                    new String[] {FROM_ELEMENT_SELECTOR_CONTENT, FROM_ELEMENT_SELECTOR_ATTRIBUTE},
                    za.isReturningAttribute()
                            ? FROM_ELEMENT_SELECTOR_ATTRIBUTE
                            : FROM_ELEMENT_SELECTOR_CONTENT);
            this.addTextField(
                    FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME,
                    za.getReturnedAttributeName());
            initElementsSelector();
            this.addFieldListener(
                    FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR, e -> initElementsSelector());

            setFieldMainPopupMenu(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME);
            setFieldMainPopupMenu(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME);
            setFieldMainPopupMenu(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE);
            setFieldMainPopupMenu(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX);
            setFieldMainPopupMenu(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME);
        } else if (assign instanceof ZestAssignGlobalVariable) {
            ZestAssignGlobalVariable za = (ZestAssignGlobalVariable) assign;
            addTextField(FIELD_VARIABLE, assign.getVariableName());
            addTextField(FIELD_GLOBAL_VAR, za.getGlobalVariableName());
        }

        this.addPadding();
    }

    private void initElementsSelector() {
        String value = this.getStringValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR);
        getField(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME)
                .setEnabled(FROM_ELEMENT_SELECTOR_ATTRIBUTE.equals(value));
    }

    private void addFieldListenerToSetEnabledOnCheckedChanged(
            String checkBoxName, String[] fieldNames) {
        final String localCheckBoxName = checkBoxName;
        final String[] localFieldNames = fieldNames;
        setEnabledOnCheckedChanged(localCheckBoxName, localFieldNames);
        this.addFieldListener(
                checkBoxName, e -> setEnabledOnCheckedChanged(localCheckBoxName, localFieldNames));
    }

    private void setEnabledOnCheckedChanged(String checkBoxName, String[] fieldNames) {
        Boolean checked = getBoolValue(checkBoxName);
        for (String fieldName : fieldNames) {
            getField(fieldName).setEnabled(checked);
        }
    }

    private List<String> getVariableNames(boolean editable) {
        ArrayList<String> list = new ArrayList<String>();
        if (editable) {
            list.add("");
        }
        list.addAll(script.getZestScript().getVariableNames());
        Collections.sort(list);
        return list;
    }

    private void initFormField(String value) {
        List<String> list = new ArrayList<String>();
        if (stmt instanceof ZestRequest) {
            ZestRequest req = (ZestRequest) stmt;
            if (stmt != null && req.getResponse() != null) {
                List<String> forms = org.mozilla.zest.impl.ZestUtils.getForms(req.getResponse());
                for (String form : forms) {
                    list.add(form);
                }
                this.setComboFields(FIELD_REPLACE_FORM, list, value);
                initFieldField(null);
            }
        }
    }

    private void initFieldField(String value) {
        int formIndex = -1;
        String formStr = this.getStringValue(FIELD_REPLACE_FORM);
        if (formStr != null && formStr.length() > 0) {
            formIndex = Integer.parseInt(formStr);
        }

        if (formIndex >= 0) {
            // TODO support form names too
            if (stmt instanceof ZestRequest) {
                ZestRequest req = (ZestRequest) stmt;
                if (stmt != null && req.getResponse() != null) {
                    List<String> fields =
                            org.mozilla.zest.impl.ZestUtils.getFields(req.getResponse(), formIndex);
                    this.setComboFields(FIELD_REPLACE_FIELD, fields, value);
                }
            }
        }
    }

    @Override
    public void save() {

        assign.setVariableName(this.getStringValue(FIELD_VARIABLE));

        if (assign instanceof ZestAssignFieldValue) {
            ZestAssignFieldValue za = (ZestAssignFieldValue) assign;
            if (za.getFieldDefinition() == null) {
                za.setFieldDefinition(new ZestFieldDefinition());
            }
            za.getFieldDefinition()
                    .setFormIndex(Integer.parseInt(this.getStringValue(FIELD_REPLACE_FORM)));
            za.getFieldDefinition().setFieldName(this.getStringValue(FIELD_REPLACE_FIELD));

        } else if (assign instanceof ZestAssignRandomInteger) {
            ZestAssignRandomInteger za = (ZestAssignRandomInteger) assign;
            za.setMinInt(this.getIntValue(FIELD_MIN_INT));
            za.setMaxInt(this.getIntValue(FIELD_MAX_INT));

        } else if (assign instanceof ZestAssignRegexDelimiters) {
            ZestAssignRegexDelimiters za = (ZestAssignRegexDelimiters) assign;
            za.setLocation(this.getStringValue(FIELD_LOCATION));
            za.setPrefix(this.getStringValue(FIELD_REGEX_PREFIX));
            za.setPostfix(this.getStringValue(FIELD_REGEX_POSTFIX));

        } else if (assign instanceof ZestAssignStringDelimiters) {
            ZestAssignStringDelimiters za = (ZestAssignStringDelimiters) assign;
            za.setLocation(this.getStringValue(FIELD_LOCATION));
            za.setPrefix(this.getStringValue(FIELD_STRING_PREFIX));
            za.setPostfix(this.getStringValue(FIELD_STRING_POSTFIX));

        } else if (assign instanceof ZestAssignString) {
            ZestAssignString za = (ZestAssignString) assign;
            za.setString(this.getStringValue(FIELD_STRING));

        } else if (assign instanceof ZestAssignReplace) {
            ZestAssignReplace za = (ZestAssignReplace) assign;
            za.setReplace(this.getStringValue(FIELD_REPLACE));
            za.setReplacement(this.getStringValue(FIELD_REPLACEMENT));
            za.setRegex(this.getBoolValue(FIELD_REGEX));
            za.setCaseExact(this.getBoolValue(FIELD_EXACT));
        } else if (assign instanceof ZestAssignCalc) {
            ZestAssignCalc za = (ZestAssignCalc) assign;
            za.setOperandA(this.getStringValue(FIELD_OPERAND_A));
            za.setOperandB(this.getStringValue(FIELD_OPERAND_B));
            za.setOperation(
                    ZestZapUtils.labelToCalcOperation(this.getStringValue(FIELD_OPERATION)));
        } else if (assign instanceof ZestAssignFromElement) {
            ZestAssignFromElement za = (ZestAssignFromElement) assign;
            za.removeFilter();

            if (this.getBoolValue(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT)) {
                String elementFilter = getStringValue(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME);
                za.whereElementIs(elementFilter);
            }

            if (this.getBoolValue(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE)) {
                String attributeFilterName =
                        getStringValue(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME);
                String attributeFilterValue =
                        getStringValue(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE);
                za.whereAttributeIs(attributeFilterName, attributeFilterValue);
            }

            boolean reverse = this.getBoolValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_REVERSED);
            int index = this.getIntValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX);
            za.atIndex(index, reverse);

            String value = this.getStringValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR);
            if (FROM_ELEMENT_SELECTOR_CONTENT.equals(value)) {
                za.selectContent();
            } else if (FROM_ELEMENT_SELECTOR_ATTRIBUTE.equals(value)) {
                String attributeName =
                        getStringValue(
                                FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME);
                za.selectAttributeValue(attributeName);
            }
        } else if (assign instanceof ZestAssignGlobalVariable) {
            ZestAssignGlobalVariable za = (ZestAssignGlobalVariable) assign;
            za.setGlobalVariableName(getStringValue(FIELD_GLOBAL_VAR));
        }

        if (add) {
            if (stmt == null) {
                extension.addToParent(parent, assign);
            } else {
                extension.addAfterRequest(parent, child, stmt, assign);
            }
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {

        if (!ZestZapUtils.isValidVariableName(this.getStringValue(FIELD_VARIABLE))
                && !this.getVariableNames(false).contains(this.getStringValue(FIELD_VARIABLE))) {
            return Constant.messages.getString("zest.dialog.assign.error.variable");
        }

        if (assign instanceof ZestAssignFieldValue) {
            if (this.isEmptyField(FIELD_REPLACE_FORM)) {
                return Constant.messages.getString("zest.dialog.assign.error.repform");
            }
            if (this.isEmptyField(FIELD_REPLACE_FIELD)) {
                return Constant.messages.getString("zest.dialog.assign.error.repfield");
            }

        } else if (assign instanceof ZestAssignRandomInteger) {
            if (this.getIntValue(FIELD_MIN_INT) >= this.getIntValue(FIELD_MAX_INT)) {
                return Constant.messages.getString("zest.dialog.assign.error.minint");
            }

        } else if (assign instanceof ZestAssignRegexDelimiters) {
            if (this.isEmptyField(FIELD_REGEX_PREFIX)) {
                return Constant.messages.getString("zest.dialog.assign.error.regexprefix");
            }
            try {
                Pattern.compile(this.getStringValue(FIELD_REGEX_PREFIX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.assign.error.regexprefix");
            }

            if (this.isEmptyField(FIELD_REGEX_POSTFIX)) {
                return Constant.messages.getString("zest.dialog.assign.error.regexpostfix");
            }
            try {
                Pattern.compile(this.getStringValue(FIELD_REGEX_POSTFIX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.assign.error.regexpostfix");
            }

        } else if (assign instanceof ZestAssignStringDelimiters) {
            if (this.isEmptyField(FIELD_STRING_PREFIX)) {
                return Constant.messages.getString("zest.dialog.assign.error.strprefix");
            }

            if (this.isEmptyField(FIELD_STRING_POSTFIX)) {
                return Constant.messages.getString("zest.dialog.assign.error.strpostfix");
            }

        } else if (assign instanceof ZestAssignString) {
            // No validation needed

        } else if (assign instanceof ZestAssignReplace) {
            if (this.getBoolValue(FIELD_REGEX)) {
                try {
                    Pattern.compile(this.getStringValue(FIELD_REPLACE));
                } catch (Exception e) {
                    return Constant.messages.getString("zest.dialog.assign.error.regexreplace");
                }
            }
        } else if (assign instanceof ZestAssignCalc) {
            if (this.isEmptyField(FIELD_OPERAND_A)) {
                return Constant.messages.getString("zest.dialog.assign.error.operand");
            }
            if (this.isEmptyField(FIELD_OPERAND_B)) {
                return Constant.messages.getString("zest.dialog.assign.error.operand");
            }
        } else if (assign instanceof ZestAssignFromElement) {
            if (this.getBoolValue(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT)
                    && this.isEmptyField(FIELD_FROM_ELEMENT_FILTER_BY_ELEMENT_NAME)) {
                return Constant.messages.getString("zest.dialog.assign.error.filterByElementEmpty");
            }

            if (this.getBoolValue(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE)
                    && (this.isEmptyField(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_NAME)
                            || this.isEmptyField(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE))) {
                return Constant.messages.getString(
                        "zest.dialog.assign.error.filterByAttributeEmpty");
            }

            try {
                Pattern.compile(this.getStringValue(FIELD_FROM_ELEMENT_FILTER_BY_ATTRIBUTE_VALUE));
            } catch (Exception e) {
                return Constant.messages.getString(
                        "zest.dialog.assign.error.filterByAttributeValueRegexInvalid");
            }

            if (this.isEmptyField(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX)
                    || this.getIntValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_INDEX) < 0) {
                return Constant.messages.getString(
                        "zest.dialog.assign.error.filteredElementsIndexInvalid");
            }

            if (this.isEmptyField(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR)) {
                return Constant.messages.getString(
                        "zest.dialog.assign.error.filteredElementsSelectorEmpty");
            }

            String value = this.getStringValue(FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR);
            if (FROM_ELEMENT_SELECTOR_ATTRIBUTE.equals(value)
                    && this.isEmptyField(
                            FIELD_FROM_ELEMENT_FILTERED_ELEMENTS_SELECTOR_ATTRIBUTE_NAME)) {
                return Constant.messages.getString(
                        "zest.dialog.assign.error.filteredElementsSelectorAttributeNameEmpty");
            }
        } else if (assign instanceof ZestAssignGlobalVariable) {
            if (isEmptyField(FIELD_GLOBAL_VAR)) {
                return Constant.messages.getString("zest.dialog.assign.error.globalvar");
            }
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
