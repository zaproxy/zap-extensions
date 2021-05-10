/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.swing.SwingUtilities;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

/**
 * A main {@code ScanController} of fuzzer scans.
 *
 * <p>Allows to control all fuzzer scans of several message types, for example, HTTP and WebSockets.
 */
public class FuzzersController implements ScanController<Fuzzer<? extends Message>> {

    /**
     * The {@code Lock} for exclusive access to instance variables related to multiple fuzzers.
     *
     * @see #fuzzerIdCounter
     * @see #fuzzerIdsToFuzzerMap
     */
    private final Lock fuzzersLock;

    /**
     * The counter used to give an unique ID to fuzzers.
     *
     * <p><strong>Note:</strong> All accesses (read/write) should be done while holding the {@code
     * Lock} {@code scansLock}.
     *
     * @see #fuzzersLock
     * @see #registerScan(FuzzerHandler, Fuzzer)
     */
    private int fuzzerIdCounter;

    /**
     * A map that contains all {@code Fuzzer}s created (and not yet removed) and corresponding
     * {@code FuzzerHandler}s. Used to control (i.e. pause/resume and stop) the multiple active
     * fuzzers and get its results. The instance variable is never {@code null}. The map key is the
     * ID of the fuzzer.
     *
     * <p><strong>Note:</strong> All accesses (both write and read) should be done while holding the
     * {@code Lock} {@code fuzzersLock}.
     *
     * @see #fuzzersLock
     * @see #fuzzerIdCounter
     */
    private Map<Integer, FuzzerEntry<?, ?>> fuzzerIdsToFuzzerMap;

    private FuzzersStatusPanel fuzzersStatusPanel;

    public FuzzersController() {
        fuzzersLock = new ReentrantLock();
        fuzzerIdsToFuzzerMap = new HashMap<>();
    }

    private void acquireFuzzersLock() {
        fuzzersLock.lock();
    }

    private void releaseScanStateLock() {
        fuzzersLock.unlock();
    }

    /**
     * Throws {@code UnsupportedOperationException}, the fuzzers are started by 3rd party.
     *
     * @throws UnsupportedOperationException the fuzzers are started by 3rd party.
     * @see #registerScan(FuzzerHandler, Fuzzer)
     */
    @Override
    public int startScan(
            String displayName, Target target, User user, Object[] contextSpecificObjects) {
        throw new UnsupportedOperationException(
                "Fuzzer scans are started by concrete fuzzer implementations.");
    }

    public <M extends Message, F extends Fuzzer<M>, FH extends FuzzerHandler<M, F>>
            void registerScan(FH fuzzHandler, F fuzzer) {
        acquireFuzzersLock();
        try {
            fuzzer.setScanId(fuzzerIdCounter);
            Integer id = Integer.valueOf(fuzzerIdCounter);
            fuzzerIdsToFuzzerMap.put(id, new FuzzerEntry<>(fuzzHandler, fuzzer));
            fuzzerIdCounter++;
        } finally {
            releaseScanStateLock();
        }
    }

    public FuzzResultsContentPanel<?, ?> getFuzzResultsContentPanel(Fuzzer<?> fuzzer) {
        acquireFuzzersLock();
        try {
            return getScanContentPanelHelper(
                    fuzzerIdsToFuzzerMap.get(Integer.valueOf(fuzzer.getScanId())));
        } finally {
            releaseScanStateLock();
        }
    }

    private <M extends Message, F extends Fuzzer<M>>
            FuzzResultsContentPanel<?, ?> getScanContentPanelHelper(FuzzerEntry<M, F> entry) {
        if (entry == null) {
            return null;
        }

        FuzzResultsContentPanel<M, F> panel = entry.getResultsContentPanel();
        panel.showFuzzerResults(entry.getFuzzer());
        return panel;
    }

    @Override
    public List<Fuzzer<? extends Message>> getAllScans() {
        acquireFuzzersLock();
        try {
            List<Fuzzer<? extends Message>> fuzzers = new ArrayList<>();
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                fuzzers.add(entry.getFuzzer());
            }
            return fuzzers;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public List<Fuzzer<? extends Message>> getActiveScans() {
        acquireFuzzersLock();
        try {
            List<Fuzzer<? extends Message>> fuzzers = new ArrayList<>();
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                if (!entry.getFuzzer().isStopped()) {
                    fuzzers.add(entry.getFuzzer());
                }
            }
            return fuzzers;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public Fuzzer<? extends Message> getScan(int id) {
        acquireFuzzersLock();
        try {
            FuzzerEntry<?, ?> entry = fuzzerIdsToFuzzerMap.get(Integer.valueOf(id));
            if (entry != null) {
                return entry.getFuzzer();
            }
            return null;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void stopScan(int id) {
        acquireFuzzersLock();
        try {
            FuzzerEntry<?, ?> entry = fuzzerIdsToFuzzerMap.get(Integer.valueOf(id));
            if (entry != null) {
                entry.getFuzzer().stopScan();
            }
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void stopAllScans() {
        acquireFuzzersLock();
        try {
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                entry.getFuzzer().stopScan();
            }
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void pauseScan(int id) {
        acquireFuzzersLock();
        try {
            FuzzerEntry<?, ?> entry = fuzzerIdsToFuzzerMap.get(Integer.valueOf(id));
            if (entry != null) {
                entry.getFuzzer().pauseScan();
                updateScannerUI();
            }
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void pauseAllScans() {
        acquireFuzzersLock();
        try {
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                entry.getFuzzer().pauseScan();
            }
            updateScannerUI();
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void resumeScan(int id) {
        acquireFuzzersLock();
        try {
            FuzzerEntry<?, ?> entry = fuzzerIdsToFuzzerMap.get(Integer.valueOf(id));
            if (entry != null) {
                entry.getFuzzer().resumeScan();
                updateScannerUI();
            }
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public void resumeAllScans() {
        acquireFuzzersLock();
        try {
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                entry.getFuzzer().resumeScan();
            }
            updateScannerUI();
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public Fuzzer<? extends Message> removeScan(int id) {
        acquireFuzzersLock();
        try {
            FuzzerEntry<?, ?> entry = fuzzerIdsToFuzzerMap.remove(Integer.valueOf(id));
            if (entry != null) {
                entry.notifyScannerRemoved();
                return entry.getFuzzer();
            }
            return null;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public int removeAllScans() {
        acquireFuzzersLock();
        try {
            for (FuzzerEntry<?, ?> entry : fuzzerIdsToFuzzerMap.values()) {
                entry.getFuzzer().stopScan();
                entry.notifyScannerRemoved();
            }
            int count = fuzzerIdsToFuzzerMap.size();
            fuzzerIdsToFuzzerMap.clear();
            return count;
        } finally {
            releaseScanStateLock();
        }
    }

    public void removeAllScans(FuzzerHandler<?, ?> fuzzerHandler) {
        acquireFuzzersLock();
        try {
            for (Iterator<FuzzerEntry<?, ?>> it = fuzzerIdsToFuzzerMap.values().iterator();
                    it.hasNext(); ) {
                FuzzerEntry<?, ?> entry = it.next();
                if (entry.getFuzzerHandler() == fuzzerHandler) {
                    entry.getFuzzer().stopScan();
                    entry.notifyScannerRemoved();
                    it.remove();
                }
            }
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public int removeFinishedScans() {
        acquireFuzzersLock();
        try {
            int count = 0;
            for (Iterator<FuzzerEntry<?, ?>> it = fuzzerIdsToFuzzerMap.values().iterator();
                    it.hasNext(); ) {
                FuzzerEntry<?, ?> entry = it.next();
                if (entry.getFuzzer().isStopped()) {
                    entry.notifyScannerRemoved();
                    it.remove();
                    count++;
                }
            }
            return count;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public Fuzzer<? extends Message> getLastScan() {
        throw new UnsupportedOperationException("State of last scan is not supported.");
    }

    public void setFuzzerScansPanel(FuzzersStatusPanel fuzzerScansPanel) {
        this.fuzzersStatusPanel = fuzzerScansPanel;
    }

    public <M extends Message, F extends Fuzzer<M>> List<F> getFuzzers(Class<F> fuzzerClass) {
        List<F> fuzzers = new ArrayList<>();
        acquireFuzzersLock();
        try {
            for (Iterator<FuzzerEntry<?, ?>> it = fuzzerIdsToFuzzerMap.values().iterator();
                    it.hasNext(); ) {
                Fuzzer<?> fuzzer = it.next().getFuzzer();
                if (fuzzerClass.equals(fuzzer.getClass())) {
                    fuzzers.add(fuzzerClass.cast(fuzzer));
                }
            }
        } finally {
            releaseScanStateLock();
        }
        return fuzzers;
    }

    private void updateScannerUI() {
        if (fuzzersStatusPanel == null) {
            return;
        }

        EventQueue.invokeLater(() -> fuzzersStatusPanel.updateScannerUI());
    }

    private static class FuzzerEntry<M extends Message, F extends Fuzzer<M>> {

        private final FuzzerHandler<M, F> fuzzerHandler;
        private final F fuzzer;

        public FuzzerEntry(FuzzerHandler<M, F> fuzzerHandler, F fuzzer) {
            this.fuzzer = fuzzer;
            this.fuzzerHandler = fuzzerHandler;
        }

        public FuzzResultsContentPanel<M, F> getResultsContentPanel() {
            return fuzzerHandler.getResultsContentPanel();
        }

        public FuzzerHandler<M, F> getFuzzerHandler() {
            return fuzzerHandler;
        }

        public F getFuzzer() {
            return fuzzer;
        }

        public void notifyScannerRemoved() {
            fuzzerHandler.scannerRemoved(fuzzer);
        }
    }

    void updateUiFuzzResultsContentPanels() {
        acquireFuzzersLock();
        try {
            fuzzerIdsToFuzzerMap.values().stream()
                    .map(FuzzerEntry::getResultsContentPanel)
                    .map(FuzzResultsContentPanel::getPanel)
                    .forEach(SwingUtilities::updateComponentTreeUI);
        } finally {
            releaseScanStateLock();
        }
    }
}
