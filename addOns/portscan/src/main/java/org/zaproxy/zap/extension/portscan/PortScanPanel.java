/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import java.awt.event.KeyEvent;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JScrollPane;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.common.AbstractParam;
import org.zaproxy.zap.model.GenericScanner;
import org.zaproxy.zap.model.ScanListenner;
import org.zaproxy.zap.model.ScanThread;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ScanPanel;

public class PortScanPanel extends ScanPanel implements ScanListenner {

    private static final long serialVersionUID = 1L;

    /**
     * @deprecated (5) Replaced by {@link #RESULTS_TABLE_NAME}, the results are shown in a table. It
     *     will be removed in a future release.
     */
    @Deprecated public static final String PANEL_NAME = "portscan";

    /** The name of the table that shows the port scan results. */
    public static final String RESULTS_TABLE_NAME = "PortScanResultsTable";

    private static final PortScanResultsTableModel EMPTY_TABLE_MODEL =
            new PortScanResultsTableModel();

    private JScrollPane jScrollPane = null;

    private PortScanResultsTable portScanResultsTable;

    /** @param portScanParam */
    public PortScanPanel(ExtensionPortScan extension, PortScanParam portScanParam) {
        // 'picture list' icon
        super(
                "ports",
                new ImageIcon(PortScanPanel.class.getResource("/resource/icon/16/187.png")),
                extension,
                portScanParam);

        this.setDefaultAccelerator(
                extension
                        .getView()
                        .getMenuShortcutKeyStroke(
                                KeyEvent.VK_P,
                                KeyEvent.ALT_DOWN_MASK | KeyEvent.SHIFT_DOWN_MASK,
                                false));
        this.setMnemonic(Constant.messages.getChar("ports.panel.mnemonic"));
    }

    @Override
    protected JScrollPane getWorkPanel() {
        if (jScrollPane == null) {
            jScrollPane = new JScrollPane();
            jScrollPane.setViewportView(getPortScanResultsTable());
            jScrollPane.setFont(FontUtils.getFont("Dialog"));
        }
        return jScrollPane;
    }

    @Override
    public void reset() {
        super.reset();
        this.resetPortList();
    }

    private void resetPortList() {
        portScanResultsTable.setModel(EMPTY_TABLE_MODEL);
    }

    public boolean isResultsSelectionEmpty() {
        return getPortScanResultsTable().isResultsSelectionEmpty();
    }

    public List<PortScanResultEntry> getSelectedResults() {
        return getPortScanResultsTable().getSelectedResults();
    }

    private PortScanResultsTable getPortScanResultsTable() {
        if (portScanResultsTable == null) {
            portScanResultsTable = new PortScanResultsTable(EMPTY_TABLE_MODEL);
            portScanResultsTable.setName(RESULTS_TABLE_NAME);
        }
        return portScanResultsTable;
    }

    @Override
    protected ScanThread newScanThread(String site, AbstractParam params) {
        return new PortScan(site, this, (PortScanParam) params);
    }

    @Override
    protected void switchView(String site) {
        if (site == null || site.isEmpty()) {
            resetPortList();
            return;
        }

        if (site.indexOf(":") >= 0) {
            // Strip off port
            site = site.substring(0, site.indexOf(":"));
        }
        GenericScanner thread = this.getScanThread(site);
        if (thread != null) {
            getPortScanResultsTable().setModel(((PortScan) thread).getResultsTableModel());
        }
    }

    @Override
    protected void unload() {
        this.reset();

        super.unload();
    }
}
