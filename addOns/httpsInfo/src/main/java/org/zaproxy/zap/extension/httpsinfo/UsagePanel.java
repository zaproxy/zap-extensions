package org.zaproxy.zap.extension.httpsinfo;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.view.View;

import javax.swing.*;
import java.awt.*;

public class UsagePanel extends AbstractPanel {

    private static final long serialVersionUID = 2L;
    private JPanel panel;
    private JTextArea tf;
    private final ViewDelegate view;

    public UsagePanel(View view){
        super();
        this.view = view;
        initialize();
    }

    private void initialize() {
        this.setLayout(new BorderLayout());
        if (Model.getSingleton().getOptionsParam().getViewParam().getWmUiHandlingOption() == 0) {
            this.setSize(600, 200);
        }
        this.add(getHistoryPanel(), java.awt.BorderLayout.CENTER);
    }

    private javax.swing.JPanel getHistoryPanel() {
        if (panel == null) {

            panel = new javax.swing.JPanel();
            panel.setLayout(new java.awt.BorderLayout());
            panel.setName("HTTPSInfo");

            panel.add(this.getTextArea());
        }
        return panel;
    }

    private JTextArea getTextArea(){
        if (tf == null){
            tf = new JTextArea("To start an HTTPS assessment choose 'Scan HTTPS Configuration' from the context menu (right click) on a Sites Tree or History entry");
            //tf.setEnabled(true);
            tf.setEditable(false);
        }

        return tf;
    }

}
