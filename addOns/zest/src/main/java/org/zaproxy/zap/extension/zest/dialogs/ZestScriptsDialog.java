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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import org.apache.log4j.Logger;
import org.mozilla.zest.core.v1.ZestAuthentication;
import org.mozilla.zest.core.v1.ZestHttpAuthentication;
import org.mozilla.zest.core.v1.ZestJSON;
import org.mozilla.zest.core.v1.ZestScript;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.extension.zest.ZestScriptWrapper;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ZestScriptsDialog extends StandardFieldsDialog {

    private static final String FIELD_TITLE = "zest.dialog.script.label.title";
    private static final String FIELD_TYPE = "zest.dialog.script.label.type";
    private static final String FIELD_FILE = "zest.dialog.script.label.file";
    private static final String FIELD_PREFIX = "zest.dialog.script.label.prefix";
    private static final String FIELD_DESC = "zest.dialog.script.label.desc";
    private static final String FIELD_AUTH_SITE = "zest.dialog.script.label.authsite";
    private static final String FIELD_AUTH_REALM = "zest.dialog.script.label.authrealm";
    private static final String FIELD_AUTH_USER = "zest.dialog.script.label.authuser";
    private static final String FIELD_AUTH_PASSWORD = "zest.dialog.script.label.authpwd";
    private static final String FIELD_STATUS = "zest.dialog.script.label.statuscode";
    private static final String FIELD_LENGTH = "zest.dialog.script.label.length";
    private static final String FIELD_APPROX = "zest.dialog.script.label.approx";
    private static final String FIELD_LOAD = "zest.dialog.script.label.load";
    private static final String FIELD_DEBUG = "zest.dialog.script.label.debug";

    private static final Logger logger = Logger.getLogger(ZestScriptsDialog.class);

    private static final long serialVersionUID = 1L;

    private ExtensionZest extension = null;
    private ScriptNode scriptNode = null;
    private ZestScriptWrapper scriptWrapper = null;
    private ZestScript script = null;
    private boolean add = false;
    private boolean chooseType = false;
    private ZestScript.Type type;
    // Need the saved boolean for deciding if we need to cancel the record button
    private boolean saved = false;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable paramsTable = null;
    private ScriptTokensTableModel paramsModel = null;
    private ZestParameterDialog parmaDialog = null;

    private List<HttpMessage> deferedMessages = new ArrayList<HttpMessage>();

    public ZestScriptsDialog(ExtensionZest ext, Frame owner, Dimension dim) {
        super(
                owner,
                "zest.dialog.script.add.title",
                dim,
                new String[] {
                    "zest.dialog.script.tab.main",
                    "zest.dialog.script.tab.tokens",
                    "zest.dialog.script.tab.auth",
                    "zest.dialog.script.tab.defaults"
                });
        this.extension = ext;
    }

    public void init(ScriptNode scriptNode, ZestScriptWrapper scriptWrapper, boolean add) {
        this.init(scriptNode, scriptWrapper, add, false);
    }

    public void init(
            ScriptNode scriptNode,
            ZestScriptWrapper scriptWrapper,
            boolean add,
            boolean chooseType) {
        this.scriptNode = scriptNode;
        this.scriptWrapper = scriptWrapper;
        this.script = scriptWrapper.getZestScript();
        this.add = add;
        this.chooseType = chooseType;
        this.saved = false;

        if (scriptWrapper.getZestScript().getType() != null) {
            // Loop through all the values so we can do a case ignore match
            for (ZestScript.Type t : ZestScript.Type.values()) {
                if (t.name().equalsIgnoreCase(scriptWrapper.getZestScript().getType())) {
                    this.type = t;
                    break;
                }
            }
        } else {
            this.type = ZestScript.Type.StandAlone;
        }

        this.removeAllFields();

        if (add) {
            this.setTitle(Constant.messages.getString("zest.dialog.script.add.title"));
        } else {
            this.setTitle(Constant.messages.getString("zest.dialog.script.edit.title"));
        }
        this.addTextField(0, FIELD_TITLE, script.getTitle());
        if (this.chooseType) {
            List<String> types = new ArrayList<String>();
            for (ScriptType st : extension.getExtScript().getScriptTypes()) {
                if (st.hasCapability(ScriptType.CAPABILITY_APPEND)) {
                    types.add(Constant.messages.getString(st.getI18nKey()));
                }
            }
            this.addComboField(
                    0,
                    FIELD_TYPE,
                    types,
                    Constant.messages.getString(
                            extension
                                    .getExtScript()
                                    .getScriptType(ExtensionScript.TYPE_STANDALONE)
                                    .getI18nKey()),
                    false);
        }
        this.addReadOnlyField(0, FIELD_FILE, "", false);
        this.addComboField(0, FIELD_PREFIX, this.getSites(), script.getPrefix(), true);
        this.addCheckBoxField(0, FIELD_LOAD, scriptWrapper.isLoadOnStart());
        this.addMultilineField(0, FIELD_DESC, script.getDescription());
        this.addCheckBoxField(0, FIELD_DEBUG, scriptWrapper.isDebug());

        if (scriptWrapper.getFile() != null) {
            this.setFieldValue(FIELD_FILE, scriptWrapper.getFile().getAbsolutePath());
            // Add tooltip in case file name is longer than the dialog
            ((JLabel) this.getField(FIELD_FILE))
                    .setToolTipText(scriptWrapper.getFile().getAbsolutePath());
        }
        this.getParamsModel().setValues(script.getParameters().getVariables());

        List<JButton> buttons = new ArrayList<JButton>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(1, this.getParamsTable(), buttons);

        if (ZestScript.Type.StandAlone.equals(this.type)) {
            // These fields are only relevant for standalone scripts
            boolean addedAuth = false;
            if (script.getAuthentication() != null && script.getAuthentication().size() > 0) {
                // Just support one for now
                ZestAuthentication auth = script.getAuthentication().get(0);
                if (auth instanceof ZestHttpAuthentication) {
                    ZestHttpAuthentication zha = (ZestHttpAuthentication) auth;
                    this.addTextField(2, FIELD_AUTH_SITE, zha.getSite());
                    this.addTextField(2, FIELD_AUTH_REALM, zha.getRealm());
                    this.addTextField(2, FIELD_AUTH_USER, zha.getUsername());
                    this.addTextField(2, FIELD_AUTH_PASSWORD, zha.getPassword());
                    this.addPadding(2);
                    addedAuth = true;
                }
            }
            if (!addedAuth) {
                this.addTextField(2, FIELD_AUTH_SITE, "");
                this.addTextField(2, FIELD_AUTH_REALM, "");
                this.addTextField(2, FIELD_AUTH_USER, "");
                this.addTextField(2, FIELD_AUTH_PASSWORD, "");
                this.addPadding(2);
            }

            this.addCheckBoxField(3, FIELD_STATUS, scriptWrapper.isIncStatusCodeAssertion());
            this.addCheckBoxField(3, FIELD_LENGTH, scriptWrapper.isIncLengthAssertion());
            this.addNumberField(3, FIELD_APPROX, 0, 100, scriptWrapper.getLengthApprox());
            this.addPadding(3);
        }

        // this.requestFocus(FIELD_TITLE);
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.add"));
            this.addButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            ZestParameterDialog dialog = getParamDialog();
                            if (!dialog.isVisible()) {
                                dialog.init(scriptWrapper, "", "", true, -1, true);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.modify"));
            this.modifyButton.setEnabled(false);
            this.modifyButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            ZestParameterDialog dialog = getParamDialog();
                            if (!dialog.isVisible()) {
                                int row = getParamsTable().getSelectedRow();
                                dialog.init(
                                        scriptWrapper,
                                        (String) getParamsModel().getValueAt(row, 0),
                                        (String) getParamsModel().getValueAt(row, 1),
                                        false,
                                        row,
                                        true);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("zest.dialog.script.button.remove"));
            this.removeButton.setEnabled(false);
            final ZestScriptsDialog parent = this;
            this.removeButton.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            if (JOptionPane.OK_OPTION
                                    == View.getSingleton()
                                            .showConfirmDialog(
                                                    parent,
                                                    Constant.messages.getString(
                                                            "zest.dialog.script.remove.confirm"))) {
                                getParamsModel().remove(getParamsTable().getSelectedRow());
                            }
                        }
                    });
        }
        return this.removeButton;
    }

    private ZestParameterDialog getParamDialog() {
        if (this.parmaDialog == null) {
            this.parmaDialog =
                    new ZestParameterDialog(this.getParamsModel(), this, new Dimension(300, 200));
        }
        return this.parmaDialog;
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

    private JTable getParamsTable() {
        if (paramsTable == null) {
            paramsTable = new JTable();
            paramsTable.setModel(getParamsModel());
            paramsTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            new ListSelectionListener() {
                                @Override
                                public void valueChanged(ListSelectionEvent e) {
                                    if (getParamsTable().getSelectedRowCount() == 0) {
                                        modifyButton.setEnabled(false);
                                        removeButton.setEnabled(false);
                                    } else if (getParamsTable().getSelectedRowCount() == 1) {
                                        modifyButton.setEnabled(true);
                                        removeButton.setEnabled(true);
                                    } else {
                                        modifyButton.setEnabled(false);
                                        // TODO allow multiple deletions?
                                        removeButton.setEnabled(false);
                                    }
                                }
                            });
        }
        return paramsTable;
    }

    private ScriptTokensTableModel getParamsModel() {
        if (paramsModel == null) {
            paramsModel = new ScriptTokensTableModel();
        }
        return paramsModel;
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

    @Override
    public void save() {
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

        Map<String, String> map = new HashMap<String, String>();
        for (String nv[] : getParamsModel().getValues()) {
            map.put(nv[0], nv[1]);
        }
        script.getParameters().setVariable(map);

        scriptWrapper.setName(script.getTitle());
        scriptWrapper.setDescription(script.getDescription());
        scriptWrapper.setContents(ZestJSON.toString(script));
        scriptWrapper.setLoadOnStart(this.getBoolValue(FIELD_LOAD));
        scriptWrapper.setDebug(this.getBoolValue(FIELD_DEBUG));

        if (add) {
            if (this.chooseType) {
                scriptWrapper.setType(this.getSelectedType());
            }

            script.setType(type);
            if (ZestScript.Type.StandAlone.equals(type)) {
                // Only need to handle standalone scripts here - rest handled by templates
                scriptWrapper.setIncStatusCodeAssertion(this.getBoolValue(FIELD_STATUS));
                scriptWrapper.setIncLengthAssertion(this.getBoolValue(FIELD_LENGTH));
                scriptWrapper.setLengthApprox(this.getIntValue(FIELD_APPROX));

                Map<String, String> tokens = new HashMap<String, String>();
                for (String[] nv : getParamsModel().getValues()) {
                    tokens.put(nv[0], nv[1]);
                }

                script.getParameters().setVariable(tokens);

                // Just support one auth for now
                script.setAuthentication(new ArrayList<ZestAuthentication>());
                if (!this.isEmptyField(FIELD_AUTH_SITE)) {
                    ZestHttpAuthentication zha = new ZestHttpAuthentication();
                    zha.setSite(this.getStringValue(FIELD_AUTH_SITE));
                    zha.setRealm(this.getStringValue(FIELD_AUTH_REALM));
                    zha.setUsername(this.getStringValue(FIELD_AUTH_USER));
                    zha.setPassword(this.getStringValue(FIELD_AUTH_PASSWORD));
                    script.addAuthentication(zha);
                }
            }

            scriptNode = extension.add(scriptWrapper, false);
            // Add any defered messages
            for (HttpMessage msg : deferedMessages) {
                logger.debug(
                        "Adding defered message: " + msg.getRequestHeader().getURI().toString());
                extension.addToParent(scriptNode, msg, null);
            }
            deferedMessages.clear();
        }
        extension.updated(scriptNode);
        this.saved = true;
    }

    @Override
    public void setVisible(boolean vis) {
        if (!vis && !saved) {
            // Cancel recording if switched on
            if (this.scriptWrapper != null && this.scriptWrapper.isRecording()) {
                extension.cancelScriptRecording();
            }
        }
        super.setVisible(vis);
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
        if (!this.getStringValue(FIELD_TITLE).equals(script.getTitle())
                && extension.getExtScript().getScript(this.getStringValue(FIELD_TITLE)) != null) {
            // Trying to change the name to one used by another script
            return Constant.messages.getString("zest.dialog.script.error.duplicate");
        }

        return null;
    }

    public void addDeferedMessage(HttpMessage msg) {
        this.deferedMessages.add(msg);

        if (this.isEmptyField(FIELD_AUTH_SITE)) {
            try {
                // Check to see if basic authentication was used
                HttpRequestHeader header = msg.getRequestHeader();
                String auth = header.getHeader(HttpHeader.AUTHORIZATION);
                if (auth != null && auth.length() > 0) {
                    if (auth.toLowerCase().startsWith("basic ")) {
                        String userPword =
                                new String(Base64.getDecoder().decode(auth.substring(6)));
                        int colon = userPword.indexOf(":");
                        if (colon > 0) {
                            this.setFieldValue(FIELD_AUTH_SITE, header.getHostName());
                            this.setFieldValue(FIELD_AUTH_USER, userPword.substring(0, colon));
                            this.setFieldValue(FIELD_AUTH_PASSWORD, userPword.substring(colon + 1));
                        }
                    }
                }
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }
}
