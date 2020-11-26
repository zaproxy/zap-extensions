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
import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.JFileChooser;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestLoop;
import org.zaproxy.zest.core.v1.ZestLoopClientElements;
import org.zaproxy.zest.core.v1.ZestLoopFile;
import org.zaproxy.zest.core.v1.ZestLoopInteger;
import org.zaproxy.zest.core.v1.ZestLoopRegex;
import org.zaproxy.zest.core.v1.ZestLoopString;
import org.zaproxy.zest.core.v1.ZestLoopTokenFileSet;
import org.zaproxy.zest.core.v1.ZestLoopTokenIntegerSet;
import org.zaproxy.zest.core.v1.ZestLoopTokenStringSet;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

public class ZestLoopDialog extends StandardFieldsDialog implements ZestDialog {
    private static final long serialVersionUID = 3720969585202318312L;

    private ZestScriptWrapper script = null;
    private ExtensionZest extension = null;
    private ScriptNode parent = null;
    private List<ScriptNode> children = null;
    private ZestStatement request = null;
    private ZestLoop<?> loop = null;
    private boolean add = false;
    private boolean surround = false;

    private static final String VARIABLE_NAME = "zest.dialog.loop.variable.name";

    private static final String VALUES_STRING = "zest.dialog.loop.string.values";

    private static final String CATEGORY_FUZZ = "zest.dialog.loop.file.fuzz.categories";
    private static final String FILE_FUZZ = "zest.dialog.loop.file.fuzz.files";
    private static final String FILE_PATH = "zest.dialog.loop.file.fuzz.path";

    private static final String START_INTEGER = "zest.dialog.loop.integer.start";
    private static final String END_INTEGER = "zest.dialog.loop.integer.end";
    private static final String STEP_INTEGER = "zest.dialog.loop.integer.step";

    private static final String FIELD_INPUT_VAR = "zest.dialog.loop.regex.input";
    private static final String FIELD_REGEX = "zest.dialog.loop.regex.regex";
    private static final String FIELD_EXACT = "zest.dialog.loop.regex.exact";
    private static final String FIELD_GROUP = "zest.dialog.loop.regex.group";

    private static final Logger logger = Logger.getLogger(ZestLoopDialog.class);

    public ZestLoopDialog(ExtensionZest extension, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.loop.add.title", dim);
        this.extension = extension;
    }

    public void init(
            ZestScriptWrapper script,
            ScriptNode parent,
            List<ScriptNode> children,
            ZestStatement req,
            ZestLoop<?> loop,
            boolean add,
            boolean surround) {
        this.script = script;
        this.add = add;
        this.parent = parent;
        this.children = children;
        this.request = req;
        this.loop = loop;
        this.surround = surround;
        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.loop.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.loop.edit.title"));
        }
        this.addTextField(VARIABLE_NAME, loop.getVariableName());
        if (loop instanceof ZestLoopString) {
            drawLoopStringDialog((ZestLoopString) this.loop);
        } else if (loop instanceof ZestLoopFile) {
            drawLoopFileDialog((ZestLoopFile) this.loop);
        } else if (loop instanceof ZestLoopInteger) {
            drawLoopIntegerDialog((ZestLoopInteger) this.loop);
        } else if (loop instanceof ZestLoopClientElements) {
            drawLoopClientElementsDialog((ZestLoopClientElements) this.loop);
        } else if (loop instanceof ZestLoopRegex) {
            drawLoopRegexDialog((ZestLoopRegex) this.loop);
        } else {
            throw new IllegalStateException(
                    "Unknown loop type: " + this.loop.getClass().getCanonicalName());
        }
        this.addPadding();
    }

    private void drawLoopStringDialog(ZestLoopString loop) {
        if (loop.getValues() != null) {
            StringBuilder allValues = new StringBuilder();
            for (String token : loop.getValues()) {
                allValues.append(token);
                allValues.append("\n");
            }
            this.addMultilineField(VALUES_STRING, allValues.toString());
        } else {
            this.addMultilineField(VALUES_STRING, "");
        }
    }

    private void drawLoopFileDialog(ZestLoopFile loop) {
        String path = "";
        if (loop.getFile() != null) {
            path = loop.getFile().getAbsolutePath();
        }

        this.addComboField(CATEGORY_FUZZ, extension.getFuzzerDelegate().getAllFuzzCategories(), "");
        this.addComboField(
                FILE_FUZZ,
                extension
                        .getFuzzerDelegate()
                        .getFuzzersForCategory(this.getStringValue(CATEGORY_FUZZ)),
                "");
        this.addFileSelectField(FILE_PATH, new File(path), JFileChooser.FILES_ONLY, null);
        this.addFieldListener(
                CATEGORY_FUZZ,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent arg0) {
                        setComboFields(
                                FILE_FUZZ,
                                extension
                                        .getFuzzerDelegate()
                                        .getFuzzersForCategory(getStringValue(CATEGORY_FUZZ)),
                                "");
                    }
                });
        this.addFieldListener(
                FILE_FUZZ,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent arg0) {
                        File f =
                                extension
                                        .getFuzzerDelegate()
                                        .getFuzzerFile(
                                                getStringValue(CATEGORY_FUZZ),
                                                getStringValue(FILE_FUZZ));

                        if (f != null && f.exists()) {
                            setFieldValue(FILE_PATH, f.getAbsolutePath());
                        }
                    }
                });
    }

    private void drawLoopIntegerDialog(ZestLoopInteger loop) {
        this.addNumberField(START_INTEGER, Integer.MIN_VALUE, Integer.MAX_VALUE, loop.getStart());
        this.addNumberField(END_INTEGER, Integer.MIN_VALUE, Integer.MAX_VALUE, loop.getEnd());
        this.addNumberField(STEP_INTEGER, 1, Integer.MAX_VALUE, loop.getCurrentToken());
    }

    private void drawLoopClientElementsDialog(ZestLoopClientElements loop) {
        // Pull down of all the valid window ids
        ZestScript script = extension.getZestTreeModel().getScriptWrapper(parent).getZestScript();
        List<String> windowIds = new ArrayList<String>(script.getClientWindowHandles());
        Collections.sort(windowIds);
        this.addComboField(
                ZestClientElementDialog.FIELD_WINDOW_HANDLE, windowIds, loop.getWindowHandle());

        String clientType = loop.getType();
        if (clientType != null && clientType.length() > 0) {
            clientType =
                    Constant.messages.getString(
                            ZestClientElementDialog.ELEMENT_TYPE_PREFIX + clientType.toLowerCase());
        }
        this.addComboField(
                ZestClientElementDialog.FIELD_ELEMENT_TYPE, getElementTypeFields(), clientType);
        this.addTextField(ZestClientElementDialog.FIELD_ELEMENT, loop.getElement());

        setFieldMainPopupMenu(ZestClientElementDialog.FIELD_ELEMENT);
    }

    private void drawLoopRegexDialog(ZestLoopRegex loop) {
        this.addComboField(FIELD_INPUT_VAR, getVariableNames(), loop.getInputVariableName());
        this.addTextField(FIELD_REGEX, loop.getRegex());
        this.addComboField(FIELD_GROUP, new int[] {0, 1, 2, 3, 4, 5}, loop.getGroupIndex());
        this.addCheckBoxField(FIELD_EXACT, loop.isCaseExact());
    }

    private List<String> getVariableNames() {
        ArrayList<String> list = new ArrayList<String>();
        list.addAll(script.getZestScript().getVariableNames());
        Collections.sort(list);
        return list;
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

    @Override
    public void save() {
        if (this.loop instanceof ZestLoopString) {
            ZestLoopString loopString = (ZestLoopString) this.loop;
            ZestLoopTokenStringSet newSet = new ZestLoopTokenStringSet();
            String[] strs = this.getStringValue(VALUES_STRING).split("\n");
            for (String str : strs) {
                newSet.addToken(str);
            }
            loopString.setSet(newSet);
        } else if (this.loop instanceof ZestLoopFile) {
            ZestLoopFile loopFile = (ZestLoopFile) this.loop;
            try {
                File selectedFile = new File(this.getStringValue(FILE_PATH));
                ZestLoopTokenFileSet fileSet =
                        new ZestLoopTokenFileSet(selectedFile.getAbsolutePath());
                loopFile.setSet(fileSet);
            } catch (FileNotFoundException e) {
                logger.error(e.getMessage(), e);
            }
        } else if (this.loop instanceof ZestLoopInteger) {
            ZestLoopInteger loopInteger = (ZestLoopInteger) this.loop;
            int start = this.getIntValue(START_INTEGER);
            int end = this.getIntValue(END_INTEGER);
            int step = this.getIntValue(STEP_INTEGER);
            ZestLoopTokenIntegerSet newSet = new ZestLoopTokenIntegerSet(start, end);
            loopInteger.setSet(newSet);
            loopInteger.setStep(step);
        } else if (loop instanceof ZestLoopClientElements) {
            ZestLoopClientElements loopCe = (ZestLoopClientElements) this.loop;
            loopCe.setType(this.getSelectedElementType());
            loopCe.setWindowHandle(
                    this.getStringValue(ZestClientElementDialog.FIELD_WINDOW_HANDLE));
            loopCe.setElement(this.getStringValue(ZestClientElementDialog.FIELD_ELEMENT));
            loopCe.setAttribute(this.getStringValue(ZestClientElementDialog.FIELD_ATTRIBUTE));
        } else if (loop instanceof ZestLoopRegex) {
            ZestLoopRegex loopRe = (ZestLoopRegex) this.loop;
            loopRe.setInputVariableName(this.getStringValue(FIELD_INPUT_VAR));
            loopRe.setRegex(this.getStringValue(FIELD_REGEX));
            loopRe.setGroupIndex(this.getIntValue(FIELD_GROUP));
            loopRe.setCaseExact(this.getBoolValue(FIELD_EXACT));
        }
        this.loop.setVariableName(this.getStringValue(VARIABLE_NAME));
        if (add) {
            if (request == null) {
                if (surround) {
                    for (ScriptNode node : children) {
                        extension.delete(node);
                        ZestStatement stmt = (ZestStatement) ZestZapUtils.getElement(node);
                        loop.addStatement(stmt);
                    }
                }
                extension.addToParent(parent, this.loop);
            } else {
                for (ScriptNode child : children) {
                    extension.addAfterRequest(parent, child, request, this.loop);
                }
            }
        } else {
            for (ScriptNode child : children) {
                extension.updated(child);
                extension.display(child, true);
            }
        }
    }

    @Override
    public String validateFields() {
        if (!ZestZapUtils.isValidVariableName(this.getStringValue(VARIABLE_NAME))) {
            return Constant.messages.getString("zest.dialog.loop.string.error.variable");
        }

        if (this.loop instanceof ZestLoopString) {
            if (this.isEmptyField(VALUES_STRING)) {
                return Constant.messages.getString("zest.dialog.loop.string.error.values");
            }
        } else if (this.loop instanceof ZestLoopFile) {
            File fileProposed = new File(this.getStringValue(FILE_PATH));
            if (fileProposed == null || !fileProposed.exists()) {
                return Constant.messages.getString("zest.dialog.loop.file.error.nonexisting");
            }
        } else if (this.loop instanceof ZestLoopInteger) {
            if (this.getIntValue(START_INTEGER) > this.getIntValue(END_INTEGER)) {
                return Constant.messages.getString("zest.dialog.loop.integer.error.constraints");
            }
        } else if (loop instanceof ZestLoopClientElements) {
            if (this.isEmptyField(ZestClientElementDialog.FIELD_ELEMENT)) {
                return Constant.messages.getString("zest.dialog.client.error.element");
            }
        } else if (loop instanceof ZestLoopRegex) {
            if (this.isEmptyField(FIELD_REGEX)) {
                return Constant.messages.getString("zest.dialog.loop.regex.error.regex");
            }
            try {
                Pattern.compile(this.getStringValue(FIELD_REGEX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.loop.error.regex");
            }
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return this.script;
    }
}
