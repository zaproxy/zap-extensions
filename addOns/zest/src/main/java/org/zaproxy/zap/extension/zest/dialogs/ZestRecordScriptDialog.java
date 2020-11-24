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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zest.core.v1.ZestJSON;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.impl.ZestScriptEngineFactory;

public class ZestRecordScriptDialog extends StandardFieldsDialog {

    private static final String FIELD_TITLE = "zest.dialog.script.label.title";
    private static final String FIELD_PREFIX = "zest.dialog.script.label.prefix";
    private static final String FIELD_DESC = "zest.dialog.script.label.desc";
    private static final String FIELD_STATUS = "zest.dialog.script.label.statuscode";
    private static final String FIELD_RECORD = "zest.dialog.script.label.record";
    private static final String FIELD_TYPE = "zest.dialog.script.label.type";
    private static final String FIELD_LENGTH = "zest.dialog.script.label.length";
    private static final String FIELD_APPROX = "zest.dialog.script.label.approx";
    private static final String FIELD_LOAD = "zest.dialog.script.label.load";
    private static final String FIELD_CLIENT_NODE = "zest.dialog.script.label.clientnode";

    private static final Logger logger = Logger.getLogger(ZestRecordScriptDialog.class);

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;

    public ZestRecordScriptDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(
                owner,
                "zest.dialog.script.record.title",
                dim,
                new String[] {"zest.dialog.script.tab.main", "zest.dialog.script.tab.defaults"});
        this.extension = ext;
    }

    public void init(SiteNode node) {
        this.removeAllFields();

        this.addTextField(0, FIELD_TITLE, "");
        this.addComboField(0, FIELD_TYPE, this.getScriptTypes(), "", false);
        this.addComboField(0, FIELD_RECORD, this.getRecordTypes(), "", false);

        this.addNodeSelectField(0, FIELD_CLIENT_NODE, node, true, false);

        this.addComboField(0, FIELD_PREFIX, this.getSites(), "", true);
        this.addCheckBoxField(0, FIELD_LOAD, true);
        this.addMultilineField(0, FIELD_DESC, "");

        this.addCheckBoxField(1, FIELD_STATUS, true);
        this.addCheckBoxField(1, FIELD_LENGTH, true);
        this.addNumberField(1, FIELD_APPROX, 0, 100, 2);
        this.addPadding(1);

        if (node != null) {
            // Its a client side script
            this.setFieldValue(
                    FIELD_RECORD,
                    Constant.messages.getString("zest.dialog.script.record.type.client"));
            getField(FIELD_PREFIX).setEnabled(false);
        } else {
            getField(FIELD_CLIENT_NODE).setEnabled(false);
        }

        this.addFieldListener(
                FIELD_RECORD,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (isServerSide()) {
                            getField(FIELD_CLIENT_NODE).setEnabled(false);
                            getField(FIELD_PREFIX).setEnabled(true);

                            getField(FIELD_STATUS).setEnabled(true);
                            getField(FIELD_LENGTH).setEnabled(true);
                            getField(FIELD_APPROX).setEnabled(true);
                        } else {
                            getField(FIELD_CLIENT_NODE).setEnabled(true);
                            getField(FIELD_PREFIX).setEnabled(false);

                            getField(FIELD_STATUS).setEnabled(false);
                            getField(FIELD_LENGTH).setEnabled(false);
                            getField(FIELD_APPROX).setEnabled(false);
                        }
                    }
                });
    }

    @Override
    public String getSaveButtonText() {
        return Constant.messages.getString("zest.dialog.script.record.save");
    }

    private List<String> getScriptTypes() {
        List<String> list = new ArrayList<String>();

        for (ScriptType st : extension.getExtScript().getScriptTypes()) {
            if (st.hasCapability(ScriptType.CAPABILITY_APPEND)) {
                list.add(Constant.messages.getString(st.getI18nKey()));
            }
        }

        return list;
    }

    private ScriptType getSelectedType() {
        for (ScriptType st : extension.getExtScript().getScriptTypes()) {
            if (this.getStringValue(FIELD_TYPE)
                    .equals(Constant.messages.getString(st.getI18nKey()))) {
                return st;
            }
        }
        return null;
    }

    private List<String> getRecordTypes() {
        List<String> list = new ArrayList<String>();
        list.add(Constant.messages.getString("zest.dialog.script.record.type.server"));
        // TODO disable until support improved...
        // list.add(Constant.messages.getString("zest.dialog.script.record.type.client"));
        return list;
    }

    private boolean isServerSide() {
        return this.getStringValue(FIELD_RECORD)
                .equals(Constant.messages.getString("zest.dialog.script.record.type.server"));
    }

    private List<String> getSites() {
        List<String> list = new ArrayList<String>();
        list.add(""); // Always start with the blank option
        SiteNode siteRoot = Model.getSingleton().getSession().getSiteTree().getRoot();
        if (siteRoot != null && siteRoot.getChildCount() > 0) {
            SiteNode child = (SiteNode) siteRoot.getFirstChild();
            while (child != null) {
                list.add(child.getHierarchicNodeName());
                child = (SiteNode) child.getNextSibling();
            }
        }
        return list;
    }

    @Override
    public void save() {
        // Create a new script

        ScriptWrapper sw = new ScriptWrapper();
        sw.setEngine(extension.getZestEngineWrapper());
        sw.setEngineName(ZestScriptEngineFactory.NAME);
        sw.setType(getSelectedType());
        ZestScriptWrapper scriptWrapper = new ZestScriptWrapper(sw);

        ZestScript script = scriptWrapper.getZestScript();

        script.setTitle(this.getStringValue(FIELD_TITLE));
        script.setDescription(this.getStringValue(FIELD_DESC));
        if (script.getPrefix() == null
                || !script.getPrefix().equals(this.getStringValue(FIELD_PREFIX))) {
            try {
                script.setPrefix(this.getStringValue(FIELD_PREFIX));
            } catch (MalformedURLException e) {
                logger.error(e.getMessage(), e);
            }
        }

        scriptWrapper.setName(script.getTitle());
        scriptWrapper.setDescription(script.getDescription());
        scriptWrapper.setContents(ZestJSON.toString(script));
        scriptWrapper.setLoadOnStart(this.getBoolValue(FIELD_LOAD));

        if (this.isServerSide()) {
            scriptWrapper.setRecording(true);

            if (ZestScript.Type.StandAlone.name().equalsIgnoreCase(script.getType())) {
                scriptWrapper.setIncStatusCodeAssertion(this.getBoolValue(FIELD_STATUS));
                scriptWrapper.setIncLengthAssertion(this.getBoolValue(FIELD_LENGTH));
                scriptWrapper.setLengthApprox(this.getIntValue(FIELD_APPROX));
            }

        } else {
            // Client side
        }

        ScriptNode scriptNode = extension.add(scriptWrapper, false);

        extension.updated(scriptNode);
        extension.setRecordingNode(scriptNode);

        if (!this.isServerSide()) {
            String url = this.getStringValue(FIELD_CLIENT_NODE);
            Extension extPnh =
                    Control.getSingleton().getExtensionLoader().getExtension("ExtensionPlugNHack");
            if (extPnh != null) {

                Method method = null;
                try {
                    URI uri = new URI(url, true);

                    extension.startClientRecording(url);

                    method = extPnh.getClass().getMethod("launchAndRecordClient", URI.class);

                    method.invoke(extPnh, uri);

                } catch (Exception e) {
                    // Its an older version, so just dont try to use it
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public void cancelPressed() {
        super.cancelPressed();
        extension.cancelScriptRecording();
    }

    @Override
    public String validateFields() {
        if (this.isEmptyField(FIELD_TITLE)) {
            return Constant.messages.getString("zest.dialog.script.error.title");
        }
        if (!this.isEmptyField(FIELD_PREFIX)) {
            try {
                new URL(this.getStringValue(FIELD_PREFIX));
            } catch (Exception e) {
                return Constant.messages.getString("zest.dialog.script.error.prefix");
            }
        }
        if (extension.getExtScript().getScript(this.getStringValue(FIELD_TITLE)) != null) {
            // Trying to change the name to one used by another script
            return Constant.messages.getString("zest.dialog.script.error.duplicate");
        }
        if (!this.isServerSide() && this.isEmptyField(FIELD_CLIENT_NODE)) {
            // Must specify a start node for client scripts
            return Constant.messages.getString("zest.dialog.script.error.clientnode");
        }

        return null;
    }
}
