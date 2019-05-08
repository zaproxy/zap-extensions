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
package org.zaproxy.zap.extension.replacer;

import java.awt.Window;
import org.parosproxy.paros.Constant;

public class ReplaceRuleModifyDialog extends ReplaceRuleAddDialog {

    private static final long serialVersionUID = 1L;

    private String originalDesc;

    public ReplaceRuleModifyDialog(
            Window owner,
            String title,
            ReplacerParam replacerParam,
            OptionsReplacerTableModel replacerModel) {
        super(owner, title, replacerParam, replacerModel);
    }

    @Override
    public void setRule(ReplacerParamRule rule) {
        super.setRule(rule);
        if (originalDesc == null) {
            originalDesc = rule.getDescription();
        }
    }

    @Override
    public void cancelPressed() {
        super.cancelPressed();
        originalDesc = null;
    }

    @Override
    public void save() {
        super.save();
        originalDesc = null;
    }

    @Override
    protected String checkIfUnique() {
        String newDesc = this.getStringValue(DESC_FIELD);
        if (!newDesc.equals(originalDesc)) {
            // Its been changed, check the new one is unique
            if (this.getReplacerModel().containsRule(newDesc)) {
                return Constant.messages.getString("replacer.add.warning.existdesc");
            }
        }
        return null;
    }
}
