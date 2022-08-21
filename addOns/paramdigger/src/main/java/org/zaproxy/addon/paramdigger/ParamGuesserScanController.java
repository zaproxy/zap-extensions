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
package org.zaproxy.addon.paramdigger;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerPanel;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

public class ParamGuesserScanController implements ScanController<GuesserScan> {
    private final Lock paramGuesserScanLock;
    private int scanIdCounter;
    private Map<Integer, GuesserScan> paramGuesserScanMap;

    private ParamDiggerPanel panel;

    public ParamGuesserScanController() {
        this.paramGuesserScanLock = new ReentrantLock();
        this.scanIdCounter = 0;
        this.paramGuesserScanMap = new HashMap<>();
    }

    public int startScan(String displayName, ParamDiggerConfig config) {
        paramGuesserScanLock.lock();
        try {
            int id = this.scanIdCounter++;
            GuesserScan paramGuesserScan = new GuesserScan(id, config, displayName);
            paramGuesserScanMap.put(id, paramGuesserScan);
            paramGuesserScan.start();

            if (panel != null) {
                panel.scannerStarted(paramGuesserScan);
                panel.setTabFocus();
            }
            return id;
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public int startScan(
            String displayName, Target target, User user, Object[] contextSpecificObjects) {
        throw new UnsupportedOperationException(
                "Scans are started with a param digger configuration.");
    }

    @Override
    public List<GuesserScan> getAllScans() {
        paramGuesserScanLock.lock();
        try {
            return new ArrayList<>(paramGuesserScanMap.values());
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public List<GuesserScan> getActiveScans() {
        List<GuesserScan> scans = new ArrayList<>();
        paramGuesserScanLock.lock();
        try {
            for (GuesserScan scan : paramGuesserScanMap.values()) {
                if (!scan.isStopped()) {
                    scans.add(scan);
                }
            }
            return scans;
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public GuesserScan getScan(int id) {
        return this.paramGuesserScanMap.get(id);
    }

    @Override
    public void stopScan(int id) {
        paramGuesserScanLock.lock();
        try {
            if (this.paramGuesserScanMap.containsKey(id)) {
                this.paramGuesserScanMap.get(id).stopScan();
                updateScansPanel();
            }
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public void stopAllScans() {
        paramGuesserScanLock.lock();
        try {
            paramGuesserScanMap.values().forEach(GuesserScan::stopScan);
            updateScansPanel();
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public void pauseScan(int id) {
        paramGuesserScanLock.lock();
        try {
            if (this.paramGuesserScanMap.containsKey(id)) {
                this.paramGuesserScanMap.get(id).pauseScan();
                updateScansPanel();
            }
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public void pauseAllScans() {
        paramGuesserScanLock.lock();
        try {
            paramGuesserScanMap.values().forEach(GuesserScan::pauseScan);
            updateScansPanel();
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public void resumeScan(int id) {
        paramGuesserScanLock.lock();
        try {
            if (this.paramGuesserScanMap.containsKey(id)) {
                this.paramGuesserScanMap.get(id).resumeScan();
                updateScansPanel();
            }
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public void resumeAllScans() {
        paramGuesserScanLock.lock();
        try {
            paramGuesserScanMap.values().forEach(GuesserScan::resumeScan);
            updateScansPanel();
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public GuesserScan removeScan(int id) {
        paramGuesserScanLock.lock();
        try {
            if (!this.paramGuesserScanMap.containsKey(id)) {
                return null;
            }
            GuesserScan currentScan = this.paramGuesserScanMap.get(id);
            currentScan.stopScan();
            currentScan.clear();
            this.paramGuesserScanMap.remove(id);
            return currentScan;
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public int removeAllScans() {
        paramGuesserScanLock.lock();
        try {
            int count = 0;
            for (Iterator<GuesserScan> it = paramGuesserScanMap.values().iterator();
                    it.hasNext(); ) {
                GuesserScan scan = it.next();
                scan.stopScan();
                scan.clear();
                it.remove();
                count++;
            }
            return count;
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public int removeFinishedScans() {
        paramGuesserScanLock.lock();
        try {
            int count = 0;
            for (Iterator<GuesserScan> it = paramGuesserScanMap.values().iterator();
                    it.hasNext(); ) {
                GuesserScan scan = it.next();
                if (scan.isStopped()) {
                    scan.stopScan();
                    scan.clear();
                    it.remove();
                    count++;
                }
            }
            return count;
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    @Override
    public GuesserScan getLastScan() {
        paramGuesserScanLock.lock();
        try {
            return paramGuesserScanMap.get(scanIdCounter - 1);
        } finally {
            paramGuesserScanLock.unlock();
        }
    }

    void setScansPanel(ParamDiggerPanel panel) {
        this.panel = panel;
    }

    private void updateScansPanel() {
        if (panel == null) {
            return;
        }

        EventQueue.invokeLater(() -> panel.updateScannerUI());
    }
}
