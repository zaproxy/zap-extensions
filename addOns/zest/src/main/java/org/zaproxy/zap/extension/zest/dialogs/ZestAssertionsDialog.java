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
import org.zaproxy.zest.core.v1.ZestAssertion;
import org.zaproxy.zest.core.v1.ZestExpressionEquals;
import org.zaproxy.zest.core.v1.ZestExpressionLength;
import org.zaproxy.zest.core.v1.ZestExpressionRegex;
import org.zaproxy.zest.core.v1.ZestExpressionStatusCode;
import org.zaproxy.zest.core.v1.ZestRequest;

public class ZestAssertionsDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_VARIABLE = "zest.dialog.assert.label.variable";
    private static final String FIELD_LENGTH = "zest.dialog.assert.label.length";
    private static final String FIELD_APPROX = "zest.dialog.assert.label.approx";
    private static final String FIELD_STATUS = "zest.dialog.assert.label.status";
    private static final String FIELD_REGEX = "zest.dialog.assert.label.regex";
    private static final String FIELD_INVERSE = "zest.dialog.assert.label.inverse";
    private static final String FIELD_VALUE = "zest.dialog.assert.label.value";
    private static final String FIELD_EXACT = "zest.dialog.assert.label.exact";

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ZestScriptWrapper script = null;
    private ScriptNode parent = null;
    private ScriptNode child = null;

    private ZestRequest request = null;
    private ZestAssertion assertion = null;
    private boolean add = false;

    public ZestAssertionsDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.assert.add.title", dim);
        this.extension = ext;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            ScriptNode child,
            ZestAssertion assertion,
            boolean add) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.child = child;
        if (child != null) {
            this.assertion = (ZestAssertion) ZestZapUtils.getElement(child);
        } else {
            this.assertion = assertion;
        }

        this.request = (ZestRequest) ZestZapUtils.getElement(parent);

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.assert.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.assert.edit.title"));
        }

        if (assertion.getRootExpression() instanceof ZestExpressionLength) {
            ZestExpressionLength za = (ZestExpressionLength) assertion.getRootExpression();
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
            this.addNumberField(FIELD_LENGTH, 0, Integer.MAX_VALUE, za.getLength());
            this.addNumberField(FIELD_APPROX, 0, 100, za.getApprox());

        } else if (assertion.getRootExpression() instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode za = (ZestExpressionStatusCode) assertion.getRootExpression();
            this.addComboField(FIELD_STATUS, HttpStatusCode.CODES, za.getCode());

        } else if (assertion.getRootExpression() instanceof ZestExpressionEquals) {
            ZestExpressionEquals za = (ZestExpressionEquals) assertion.getRootExpression();
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
            this.addTextField(FIELD_VALUE, za.getValue());
            this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());
            this.addCheckBoxField(FIELD_INVERSE, za.isInverse());

            setFieldMainPopupMenu(FIELD_VALUE);

        } else if (assertion.getRootExpression() instanceof ZestExpressionRegex) {
            ZestExpressionRegex za = (ZestExpressionRegex) assertion.getRootExpression();
            this.addComboField(FIELD_VARIABLE, this.getVariableNames(), za.getVariableName());
            this.addTextField(FIELD_REGEX, za.getRegex());
            this.addCheckBoxField(FIELD_EXACT, za.isCaseExact());
            this.addCheckBoxField(FIELD_INVERSE, za.isInverse());
        }
        this.addPadding();
    }

    private List<String> getVariableNames() {
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(script.getZestScript().getVariableNames());
        Collections.sort(list);
        return list;
    }

    @Override
    public void save() {
        if (assertion.getRootExpression() instanceof ZestExpressionLength) {
            ZestExpressionLength za = (ZestExpressionLength) assertion.getRootExpression();
            za.setVariableName(this.getStringValue(FIELD_VARIABLE));
            za.setLength(this.getIntValue(FIELD_LENGTH));
            za.setApprox(this.getIntValue(FIELD_APPROX));

        } else if (assertion.getRootExpression() instanceof ZestExpressionStatusCode) {
            ZestExpressionStatusCode za = (ZestExpressionStatusCode) assertion.getRootExpression();
            za.setCode(this.getIntValue(FIELD_STATUS));

        } else if (assertion.getRootExpression() instanceof ZestExpressionEquals) {
            ZestExpressionEquals za = (ZestExpressionEquals) assertion.getRootExpression();
            za.setVariableName(this.getStringValue(FIELD_VARIABLE));
            za.setValue(this.getStringValue(FIELD_VALUE));
            za.setCaseExact(this.getBoolValue(FIELD_EXACT));
            za.setInverse(this.getBoolValue(FIELD_INVERSE));

        } else if (assertion.getRootExpression() instanceof ZestExpressionRegex) {
            ZestExpressionRegex za = (ZestExpressionRegex) assertion.getRootExpression();
            za.setVariableName(this.getStringValue(FIELD_VARIABLE));
            za.setRegex(this.getStringValue(FIELD_REGEX));
            za.setCaseExact(this.getBoolValue(FIELD_EXACT));
            za.setInverse(this.getBoolValue(FIELD_INVERSE));
        }

        if (add) {
            extension.addToRequest(parent, request, assertion);
        } else {
            extension.updated(child);
            extension.display(child, false);
        }
    }

    @Override
    public String validateFields() {
        if (assertion.getRootExpression() instanceof ZestExpressionLength) {
            // Nothing to do

        } else if (assertion.getRootExpression() instanceof ZestExpressionStatusCode) {
            // Nothing to do

        } else if (assertion.getRootExpression() instanceof ZestExpressionRegex) {
            if (this.isEmptyField(FIELD_REGEX)) {
                return Constant.messages.getString("zest.dialog.assert.error.regex");
            }
            try {
                Pattern.compile(this.getStringValue(FIELD_REGEX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.assert.error.regex");
            }
        } else if (assertion.getRootExpression() instanceof ZestExpressionEquals) {
            if (this.isEmptyField(FIELD_VALUE)) {
                return Constant.messages.getString("zest.dialog.assert.error.value");
            }
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
