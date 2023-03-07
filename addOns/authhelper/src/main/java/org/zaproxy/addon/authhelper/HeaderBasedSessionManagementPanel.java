/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.awt.EventQueue;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Panel;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JLabel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.Pair;
import org.zaproxy.zap.utils.ZapLabel;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class HeaderBasedSessionManagementPanel extends Panel {

    private static final long serialVersionUID = 1L;

    private static final Insets STD_INSETS = new Insets(2, 2, 2, 2);

    private List<Pair<ZapTextField, ZapTextField>> fields = new ArrayList<>();

    public HeaderBasedSessionManagementPanel() {
        this.setLayout(new GridBagLayout());
        this.add(
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.session.method.header.label.header")),
                getGBC(0, 0));
        this.add(
                new JLabel(
                        Constant.messages.getString(
                                "authhelper.session.method.header.label.value")),
                getGBC(1, 0));
        addRow();
        addRow();
        ZapLabel footer =
                new ZapLabel(
                        Constant.messages.getString(
                                "authhelper.session.method.header.label.footer"));
        footer.setLineWrap(true);
        footer.setWrapStyleWord(true);
        this.add(
                footer,
                LayoutHelper.getGBC(
                        0,
                        1000,
                        2,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        GridBagConstraints.NORTHWEST,
                        STD_INSETS));
    }

    private GridBagConstraints getGBC(int x, int y) {
        return LayoutHelper.getGBC(
                x,
                y,
                1,
                1.0,
                1.0,
                GridBagConstraints.BOTH,
                GridBagConstraints.NORTHWEST,
                STD_INSETS);
    }

    private Pair<ZapTextField, ZapTextField> addRow() {
        Pair<ZapTextField, ZapTextField> pair = new Pair<>(new ZapTextField(), new ZapTextField());
        fields.add(pair);
        this.add(pair.first, getGBC(0, fields.size()));
        this.add(pair.second, getGBC(1, fields.size()));
        pair.second.addKeyListener(
                new KeyAdapter() {
                    @Override
                    public void keyReleased(KeyEvent e) {
                        super.keyReleased(e);
                        manageRows();
                    }
                });
        return pair;
    }

    private void manageRows() {
        Pair<ZapTextField, ZapTextField> last = fields.get(fields.size() - 1);
        if (!last.second.getText().isBlank()) {
            // Last field no longer blank, add another one
            EventQueue.invokeLater(
                    () -> {
                        addRow();
                        this.revalidate();
                        this.repaint();
                    });
            return;
        }
        if (fields.size() > 2 && last.first.getText().isBlank()) {
            Pair<ZapTextField, ZapTextField> prev = fields.get(fields.size() - 2);
            if (prev.first.getText().isBlank() && prev.second.getText().isBlank()) {
                // Last 2 rows now blank - remove the last one
                EventQueue.invokeLater(
                        () -> {
                            this.remove(last.first);
                            this.remove(last.second);
                            fields.remove(last);
                            this.revalidate();
                            this.repaint();
                        });
            }
        }
    }

    private Pair<ZapTextField, ZapTextField> getNextFields() {
        for (Pair<ZapTextField, ZapTextField> pair : fields) {
            if (pair.first.getText().isBlank() && pair.second.getText().isBlank()) {
                return pair;
            }
        }
        return addRow();
    }

    private void clearFields() {
        for (Pair<ZapTextField, ZapTextField> pair : fields) {
            this.remove(pair.first);
            this.remove(pair.second);
        }
        fields.clear();
        addRow();
        addRow();
        this.revalidate();
        this.repaint();
    }

    public void setHeaders(List<Pair<String, String>> headers) {
        clearFields();

        for (Pair<String, String> header : headers) {
            Pair<ZapTextField, ZapTextField> fields = getNextFields();
            fields.first.setText(header.first);
            fields.first.discardAllEdits();
            fields.second.setText(header.second);
            fields.second.discardAllEdits();
        }
        // There should always be another blank row
        getNextFields();
    }

    public List<Pair<String, String>> getHeaders() {
        List<Pair<String, String>> list = new ArrayList<>();
        for (Pair<ZapTextField, ZapTextField> pair : fields) {
            if (!pair.first.getText().isBlank() || !pair.second.getText().isBlank()) {
                list.add(new Pair<>(pair.first.getText(), pair.second.getText()));
            }
        }
        return list;
    }
}
