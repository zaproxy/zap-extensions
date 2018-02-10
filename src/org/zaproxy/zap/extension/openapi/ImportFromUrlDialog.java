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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.openapi;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTextField;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractDialog;
import org.parosproxy.paros.view.View;

public class ImportFromUrlDialog extends AbstractDialog implements ActionListener {

    private static final long serialVersionUID = -7074394202143400215L;
    private static final String MESSAGE_PREFIX = "openapi.importfromurldialog.";

    private ExtensionOpenApi caller;

    private JTextField fieldURL = new JTextField(30);
    private JTextField siteOverride = new JTextField(30);

    private JButton buttonCancel = new JButton(Constant.messages.getString("all.button.cancel"));
    private JButton buttonImport = new JButton(Constant.messages.getString(MESSAGE_PREFIX + "importbutton"));

    public ImportFromUrlDialog(JFrame parent, ExtensionOpenApi caller) {
        super(parent, true);
        this.setTitle(Constant.messages.getString(MESSAGE_PREFIX + "title"));
        this.caller = caller;
        if (parent != null) {
            Dimension parentSize = parent.getSize();
            Point p = parent.getLocation();
            setLocation(p.x + parentSize.width / 4, p.y + parentSize.height / 4);
        }
        // set up layout
        setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;
        constraints.insets = new Insets(5, 5, 5, 5);

        buttonImport.addActionListener(this);
        buttonCancel.addActionListener(new ActionListener(){
            @Override
            public void actionPerformed(ActionEvent e) {
                ImportFromUrlDialog.this.setVisible(false);
                ImportFromUrlDialog.this.dispose();
            }});

        // add components to the frame
        constraints.gridx = 0;
        constraints.gridy = 0;
        add(new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labelurl")), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 2;
        fieldURL = addContextMenu(fieldURL);
        add(fieldURL, constraints);

        constraints.gridx = 0;
        constraints.gridy = 1;
        add(new JLabel(Constant.messages.getString(MESSAGE_PREFIX + "labeloverride")), constraints);

        constraints.gridx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1.0;
        constraints.gridwidth = 2;
        add(siteOverride, constraints);
        
        constraints.gridwidth = 1;
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonCancel, constraints);
        constraints.gridx = 2;
        constraints.gridy = 2;
        constraints.anchor = GridBagConstraints.CENTER;
        add(buttonImport, constraints);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        pack();
        setVisible(true);
    }

    /* Action executed by import button. */
    @Override
    public void actionPerformed(ActionEvent e) {
        if (caller != null) {
            String url = fieldURL.getText();
            String override = siteOverride.getText();
            
            if (override.length() > 0) {
                // Check the siteOverride looks ok
                try {
                    new URI("http://" + siteOverride, true);
                } catch (Exception e1) {
                    View.getSingleton().showWarningDialog(thisDialog, 
                            Constant.messages.getString(MESSAGE_PREFIX + "badoverride", e1.getMessage()));
                    return;
                }
            }
            
            /* Calls a parsing task in a new thread. */
            try {
                caller.importOpenApiDefinition(new URI(url, false), override, true);
            } catch (URIException ex) {
                View.getSingleton().showWarningDialog(thisDialog, Constant.messages.getString(MESSAGE_PREFIX + "badurl"));
            }
        }
        setVisible(false);
        dispose();
    }

    /* Adds a context menu to URL text field with "paste" option. */
    public JTextField addContextMenu(final JTextField field) {
        JPopupMenu jPopupMenu = new JPopupMenu();
        String actionName = Constant.messages.getString(MESSAGE_PREFIX + "pasteaction");
        @SuppressWarnings("serial")
        Action pasteAction = new AbstractAction(actionName) {

            public void actionPerformed(ActionEvent e) {
                field.paste();
            }
        };
        JMenuItem paste = new JMenuItem(pasteAction);
        jPopupMenu.add(paste);
        field.setComponentPopupMenu(jPopupMenu);
        return field;
    }
}
