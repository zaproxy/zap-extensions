/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.internal.ui;

import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import javax.swing.event.EventListenerList;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import org.zaproxy.zap.extension.alertFilters.internal.ScanRulesInfo;

@SuppressWarnings("serial")
public class ScanRulesInfoComboBoxModel extends AbstractListModel<ScanRulesInfo.Entry>
        implements ComboBoxModel<ScanRulesInfo.Entry> {

    private final EventListenerList listenerList;
    private final ScanRulesInfo scanRulesInfo;
    private ScanRulesInfo.Entry selectedScanRuleInfo;

    public ScanRulesInfoComboBoxModel(ScanRulesInfo scanRulesInfo) {
        listenerList = new EventListenerList();
        this.scanRulesInfo = scanRulesInfo;
        selectedScanRuleInfo = scanRulesInfo.isEmpty() ? null : scanRulesInfo.get(0);
    }

    @Override
    public void addListDataListener(ListDataListener l) {
        listenerList.add(ListDataListener.class, l);
    }

    @Override
    public void removeListDataListener(ListDataListener l) {
        listenerList.remove(ListDataListener.class, l);
    }

    @Override
    public int getSize() {
        return scanRulesInfo.size();
    }

    @Override
    public ScanRulesInfo.Entry getElementAt(int index) {
        return scanRulesInfo.get(index);
    }

    @Override
    public void setSelectedItem(Object anItem) {
        if (anItem == null) {
            if (selectedScanRuleInfo != null) {
                selectedScanRuleInfo = null;
                notifySelectedItemChanged();
            }
            return;
        }

        if (!(anItem instanceof ScanRulesInfo.Entry) || selectedScanRuleInfo == anItem) {
            return;
        }

        selectedScanRuleInfo = (ScanRulesInfo.Entry) anItem;
        notifySelectedItemChanged();
    }

    private void notifySelectedItemChanged() {
        ListDataEvent event = null;
        Object[] listeners = listenerList.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ListDataListener.class) {
                if (event == null) {
                    event = new ListDataEvent(this, ListDataEvent.CONTENTS_CHANGED, -1, -1);
                }
                ((ListDataListener) listeners[i + 1]).contentsChanged(event);
            }
        }
    }

    @Override
    public ScanRulesInfo.Entry getSelectedItem() {
        return selectedScanRuleInfo;
    }
}
