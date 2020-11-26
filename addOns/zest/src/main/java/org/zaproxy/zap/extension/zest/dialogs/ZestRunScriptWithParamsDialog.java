/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.extension.zest.ZestZapRunner;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestScript;

public class ZestRunScriptWithParamsDialog extends StandardFieldsDialog implements ZestDialog {

    private static final String FIELD_PARAMS = "zest.dialog.run.label.params";

    private static final long serialVersionUID = 1L;

    private ZestZapRunner runner = null;
    private ZestScript script = null;

    private JTable paramsTable = null;
    private ScriptTokensTableModel paramsModel = null;

    private static final Logger logger = Logger.getLogger(ZestRunScriptWithParamsDialog.class);

    public ZestRunScriptWithParamsDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(owner, "zest.dialog.run.title", dim);
        this.setXWeights(0.2D, 0.8D);
    }

    public void init(ZestZapRunner runner, ZestScript script, Map<String, String> params) {
        this.runner = runner;
        this.script = script;

        this.removeAllFields();

        this.getParamsModel().setValues(script.getParameters().getVariables());

        for (Entry<String, String> param : params.entrySet()) {
            if (param.getValue().length() > 0) {
                // Override any defaults in the script
                this.getParamsModel().setValue(param.getKey(), param.getValue());
            }
        }
        this.addTableField(FIELD_PARAMS, this.getParamsTable());
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("zest.dialog.run.button.run");
    }

    private JTable getParamsTable() {
        if (paramsTable == null) {
            paramsTable = new JTable();
            paramsTable.setModel(getParamsModel());
        }
        return paramsTable;
    }

    private ScriptTokensTableModel getParamsModel() {
        if (paramsModel == null) {
            paramsModel = new ScriptTokensTableModel();
            paramsModel.setDirectlyEditable(true);
        }
        return paramsModel;
    }

    public Map<String, String> getParams() {
        Map<String, String> map = new HashMap<String, String>();
        for (String[] param : this.getParamsModel().getValues()) {
            map.put(param[0], param[1]);
        }
        return map;
    }

    @Override
    public void save() {
        SwingUtilities.invokeLater(
                new Runnable() {
                    @Override
                    public void run() {
                        try {
                            runner.run(script, getParams());
                        } catch (Exception e) {
                            logger.error(e.getMessage(), e);
                        }
                    }
                });
    }

    @Override
    public String validateFields() {
        // Check all variables are specified
        for (String[] param : this.getParamsModel().getValues()) {
            if (param[1].length() == 0) {
                return Constant.messages.getString("zest.dialog.run.error.missingvals");
            }
        }
        return null;
    }

    @Override
    public ZestScriptWrapper getScript() {
        return null;
    }
}
