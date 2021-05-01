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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestExpression;
import org.zaproxy.zest.core.v1.ZestExpressionClientElementExists;
import org.zaproxy.zest.core.v1.ZestExpressionEquals;
import org.zaproxy.zest.core.v1.ZestExpressionIsInteger;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionRegex;
import org.zaproxy.zest.core.v1.ZestExpressionResponseTime;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestExpressionURL;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestExpressionDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_REGEX = "zest.dialog.condition.label.regex";
    private static final String FIELD_STATUS = "zest.dialog.condition.label.status";
    private static final String FIELD_INVERSE = "zest.dialog.assert.label.inverse";
    private static final String FIELD_GREATER_THAN = "zest.dialog.condition.label.greaterthan";
    private static final String FIELD_RESP_TIME = "zest.dialog.condition.label.resptime";
    private static final String FIELD_INC_REGEXS = "zest.dialog.condition.label.incregexes";
    private static final String FIELD_EXC_REGEXS = "zest.dialog.condition.label.excregexes";
    private static final String FIELD_VARIABLE = "zest.dialog.condition.label.variable";
    private static final String FIELD_VALUE = "zest.dialog.condition.label.value";
    private static final String FIELD_EXACT = "zest.dialog.condition.label.exact";
    private static final String FIELD_LENGTH = "zest.dialog.condition.label.length";
    private static final String FIELD_APPROX = "zest.dialog.condition.label.approx";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ZestScriptWrapper script = null;
    private ScriptNode parent = null;
    private List<ScriptNode> children = null;
    private ZestStatement request = null;
    private ZestExpression expression = null;
    private boolean add = false;
    private boolean surround = false;
    // private Frame owner = null;

    private boolean addToNewConditional = false;

    public ZestExpressionDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.condition.add.title", dim);
        this.extension = ext;
        // this.owner = owner;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            List<ScriptNode> children,
            ZestStatement req,
            ZestExpression expression,
            boolean add,
            boolean surround,
            boolean addToNewConditional) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.children = children;
        this.request = req;
        this.expression = expression;
        this.surround = surround;
        this.addToNewConditional = addToNewConditional;

        this.removeAllFields();
        if (addToNewConditional) {
            if (add) {
                this.setTitle(Constant.messages.getString("zest.dialog.condition.add.title"));
            } else {
                this.setTitle(Constant.messages.getString("zest.dialog.condition.edit.title"));
            }
        } else {
            if (add) {
                this.setTitle(Constant.messages.getString("zest.dialog.expression.add.title"));
            } else {
                this.setTitle(Constant.messages.getString("zest.dialog.expression.edit.title"));
            }
        }

        if (expression instanceof ZestExpressionRegex) {
            ZestExpressionRegex za = (ZestExpressionRegex) expression;
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
            this.addTextField(FIELD_REGEX, za.getRegex());
            this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());

        } else if (expression instanceof ZestExpressionEquals) {
            ZestExpressionEquals za = (ZestExpressionEquals) expression;
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
            this.addTextField(FIELD_VALUE, za.getValue());
            this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());

            setFieldMainPopupMenu(FIELD_VALUE);

        } else if (expression instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode za = (ZestExpressionStatusCode) expression;
            this.addComboField(FIELD_STATUS, HttpStatusCode.CODES, za.getCode());

        } else if (expression instanceof ZestExpressionResponseTime) {
            ZestExpressionResponseTime zc = (ZestExpressionResponseTime) expression;
            this.addCheckBoxField(FIELD_GREATER_THAN, zc.isGreaterThan());
            this.addNumberField(FIELD_RESP_TIME, 0, Integer.MAX_VALUE, (int) zc.getTimeInMs());

        } else if (expression instanceof ZestExpressionURL) {
            ZestExpressionURL zc = (ZestExpressionURL) expression;
            this.addMultilineField(FIELD_INC_REGEXS, this.listToStr(zc.getIncludeRegexes()));
            this.addMultilineField(FIELD_EXC_REGEXS, this.listToStr(zc.getExcludeRegexes()));

        } else if (expression instanceof ZestExpressionLength) {
            ZestExpressionLength zc = (ZestExpressionLength) expression;
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), zc.getVariableName());
            this.addNumberField(FIELD_LENGTH, 0, Integer.MAX_VALUE, zc.getLength());
            this.addNumberField(FIELD_APPROX, 0, 100, zc.getApprox());

        } else if (expression instanceof ZestExpressionIsInteger) {
            ZestExpressionIsInteger zc = (ZestExpressionIsInteger) expression;
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), zc.getVariableName());

        } else if (expression instanceof ZestExpressionClientElementExists) {
            ZestExpressionClientElementExists zc = (ZestExpressionClientElementExists) expression;

            // Pull down of all the valid window ids
            List<String> windowIds =
                    new ArrayList<String>(script.getZestScript().getClientWindowHandles());
            Collections.sort(windowIds);
            this.addComboField(
                    ZestClientElementDialog.FIELD_WINDOW_HANDLE, windowIds, zc.getWindowHandle());

            String clientType = zc.getType();
            if (clientType != null) {
                clientType =
                        Constant.messages.getString(
                                ZestClientElementDialog.ELEMENT_TYPE_PREFIX
                                        + clientType.toLowerCase());
            }
            this.addComboField(
                    ZestClientElementDialog.FIELD_ELEMENT_TYPE, getElementTypeFields(), clientType);
            this.addTextField(ZestClientElementDialog.FIELD_ELEMENT, zc.getElement());

            setFieldMainPopupMenu(ZestClientElementDialog.FIELD_ELEMENT);
        }
        this.addCheckBoxField(FIELD_INVERSE, expression.isInverse());
        this.addPadding();
    }

    private List<String> getElementTypeFields() {
        List<String> list = new ArrayList<String>();
        for (String type : ZestClientElementDialog.ELEMENT_TYPES) {
            list.add(
                    Constant.messages.getString(
                            ZestClientElementDialog.ELEMENT_TYPE_PREFIX + type));
        }
        Collections.sort(list);
        return list;
    }

    private String getSelectedElementType() {
        String selectedType = this.getStringValue(ZestClientElementDialog.FIELD_ELEMENT_TYPE);
        for (String type : ZestClientElementDialog.ELEMENT_TYPES) {
            if (Constant.messages
                    .getString(ZestClientElementDialog.ELEMENT_TYPE_PREFIX + type)
                    .equals(selectedType)) {
                return type;
            }
        }
        return null;
    }

    public boolean isAddingExpressionToNewCondition() {
        return addToNewConditional;
    }

    private List<String> getVariableNames() {
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(script.getZestScript().getVariableNames());
        Collections.sort(list);
        return list;
    }

    private String listToStr(List<String> list) {
        StringBuilder sb = new StringBuilder();
        for (String str : list) {
            sb.append(str);
            sb.append("\n");
        }
        return sb.toString();
    }

    private List<String> strToList(String str) {
        List<String> list = new ArrayList<String>();
        for (String el : str.split("\n")) {
            if (el.length() > 0) {
                list.add(el);
            }
        }
        return list;
    }

    @Override
    public void save() {
        if (expression instanceof ZestExpressionRegex) {
            ZestExpressionRegex zc = (ZestExpressionRegex) expression;
            zc.setVariableName(this.getStringValue(FIELD_VARIABLE));
            zc.setRegex(this.getStringValue(FIELD_REGEX));
            zc.setCaseExact(this.getBoolValue(FIELD_EXACT));

        } else if (expression instanceof ZestExpressionEquals) {
            ZestExpressionEquals zc = (ZestExpressionEquals) expression;
            zc.setVariableName(this.getStringValue(FIELD_VARIABLE));
            zc.setValue(this.getStringValue(FIELD_VALUE));
            zc.setCaseExact(this.getBoolValue(FIELD_EXACT));

        } else if (expression instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode zc = (ZestExpressionStatusCode) expression;
            zc.setCode(this.getIntValue(FIELD_STATUS));

        } else if (expression instanceof ZestExpressionResponseTime) {
            ZestExpressionResponseTime zc = (ZestExpressionResponseTime) expression;
            zc.setGreaterThan(this.getBoolValue(FIELD_GREATER_THAN));
            zc.setTimeInMs(this.getIntValue(FIELD_RESP_TIME));

        } else if (expression instanceof ZestExpressionURL) {
            ZestExpressionURL zc = (ZestExpressionURL) expression;
            zc.setIncludeRegexes(this.strToList(this.getStringValue(FIELD_INC_REGEXS)));
            zc.setExcludeRegexes(this.strToList(this.getStringValue(FIELD_EXC_REGEXS)));

        } else if (expression instanceof ZestExpressionLength) {
            ZestExpressionLength za = (ZestExpressionLength) expression;
            za.setVariableName(this.getStringValue(FIELD_VARIABLE));
            za.setLength(this.getIntValue(FIELD_LENGTH));
            za.setApprox(this.getIntValue(FIELD_APPROX));

        } else if (expression instanceof ZestExpressionIsInteger) {
            ZestExpressionIsInteger ze = (ZestExpressionIsInteger) expression;
            ze.setVariableName(this.getStringValue(FIELD_VARIABLE));

        } else if (expression instanceof ZestExpressionClientElementExists) {
            ZestExpressionClientElementExists zc = (ZestExpressionClientElementExists) expression;
            zc.setWindowHandle(this.getStringValue(ZestClientElementDialog.FIELD_WINDOW_HANDLE));
            zc.setType(getSelectedElementType());
            zc.setElement(this.getStringValue(ZestClientElementDialog.FIELD_ELEMENT));
        }
        expression.setInverse(this.getBoolValue(FIELD_INVERSE));
        if (addToNewConditional) {
            ZestConditional condition = new ZestConditional(expression);
            if (add) {
                if (request == null) {
                    if (surround) {
                        for (ScriptNode node : children) {
                            extension.delete(node);
                            ZestStatement ifStmt = (ZestStatement) ZestZapUtils.getElement(node);
                            condition.addIf(ifStmt);
                        }
                    }
                    extension.addToParent(parent, condition);
                } else {
                    for (ScriptNode child : children) {
                        extension.addAfterRequest(parent, child, request, condition);
                    }
                }
            } else {
                for (ScriptNode child : children) {
                    extension.updated(child);
                    extension.display(child, true);
                }
            }
        } else {
            if (add) {
                ScriptNode expNode = extension.addToParent(parent, expression);
                if (surround) {
                    extension.setCnpNodes(children);
                    extension.setCut(true);
                    extension.pasteToNode(expNode);
                }
            } else {
                for (ScriptNode child : children) {
                    extension.updated(child);
                }
            }
        }
    }

    @Override
    public String validateFields() {
        if (expression instanceof ZestExpressionRegex) {
            if (this.isEmptyField(FIELD_REGEX)) {
                return Constant.messages.getString("zest.dialog.condition.error.regex");
            }
            try {
                Pattern.compile(this.getStringValue(FIELD_REGEX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.condition.error.regex");
            }
        } else if (expression instanceof ZestExpressionEquals) {
            if (this.isEmptyField(FIELD_VALUE)) {
                return Constant.messages.getString("zest.dialog.condition.error.value");
            }
        } else if (expression instanceof ZestExpressionURL) {
            try {
                for (String str : this.strToList(this.getStringValue(FIELD_INC_REGEXS))) {
                    Pattern.compile(str);
                }
                for (String str : this.strToList(this.getStringValue(FIELD_EXC_REGEXS))) {
                    Pattern.compile(str);
                }
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.condition.error.regexes");
            }

        } else if (expression instanceof ZestExpressionClientElementExists) {
            if (this.isEmptyField(ZestClientElementDialog.FIELD_ELEMENT)) {
                return Constant.messages.getString("zest.dialog.client.error.element");
            }
        }
        return null;
    }

    protected ZestConditional getCondition() {
        return new ZestConditional(expression);
    }

    protected ZestExpression getExpression() {
        return this.expression;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
