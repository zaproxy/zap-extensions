/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.authenticationhelper.ExtensionAuthenticationHelper;
import org.zaproxy.zap.extension.authenticationhelper.OptionsParamAuthenticationHelper;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

public class AuthenticationStatusScanController
        implements ScanController<AuthenticationStatusScanner> {

    private ExtensionAuthenticationHelper extAuthHelper;

    /**
     * The {@code Lock} for exclusive access of instance variables related to multiple
     * authentication status scans.
     *
     * @see #authenticationStatusScanMap
     * @see #scanIdCounter
     */
    private final Lock authenticationStatusScansLock;

    /**
     * The counter used to give an unique ID to active scans.
     *
     * <p><strong>Note:</strong> All accesses (both write and read) should be done while holding the
     * {@code Lock} {@code authenticationStatusScansLock}.
     *
     * @see #authenticationStatusScansLock
     * @see #startScan(String, Target, User, Object[])
     */
    private int scanIdCounter;

    /**
     * A map that contains all {@code AuthenticationStatusScan}s created (and not yet removed). Used
     * to control (i.e. pause/resume and stop) the multiple authentication status scans and get its
     * results. The instance variable is never {@code null}. The map key is the ID of the scan.
     *
     * <p><strong>Note:</strong> All accesses (both write and read) should be done while holding the
     * {@code Lock} {@code authenticationStatusScansLock}.
     *
     * @see #authenticationStatusScansLock
     * @see #startScan(String, Target, User, Object[])
     * @see #scanIdCounter
     */
    private Map<Integer, AuthenticationStatusScanner> authenticationStatusScanMap;

    public AuthenticationStatusScanController(ExtensionAuthenticationHelper extAuthHelper) {
        this.authenticationStatusScansLock = new ReentrantLock();
        this.extAuthHelper = extAuthHelper;
        this.authenticationStatusScanMap = new HashMap<>();
    }

    @Override
    public int startScan(
            String displayName, Target target, User user, Object[] contextSpecificObjects) {
        authenticationStatusScansLock.lock();
        try {
            int id = scanIdCounter++;

            AuthenticationStatusScanner authenticationStatusScan =
                    new AuthenticationStatusScanner(
                            extAuthHelper,
                            displayName,
                            target,
                            user,
                            id,
                            extAuthHelper.getModel().getOptionsParam().getConnectionParam());

            if (contextSpecificObjects != null) {
                for (Object obj : contextSpecificObjects) {
                    if (obj instanceof OptionsParamAuthenticationHelper) {
                        authenticationStatusScan.setOptionsParam(
                                (OptionsParamAuthenticationHelper) obj);
                    } else if (obj instanceof AuthenticationMethod) {
                        AuthenticationMethod authenticationMethod = (AuthenticationMethod) obj;
                        authenticationStatusScan.setLoggedInIndicatorPattern(
                                authenticationMethod.getLoggedInIndicatorPattern());
                        authenticationStatusScan.setLoggedOutIndicatorPattern(
                                authenticationMethod.getLoggedOutIndicatorPattern());
                    }
                }
            }

            authenticationStatusScanMap.put(id, authenticationStatusScan);
            authenticationStatusScan.start();

            return id;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public List<AuthenticationStatusScanner> getAllScans() {
        authenticationStatusScansLock.lock();
        try {
            return new ArrayList<AuthenticationStatusScanner>(authenticationStatusScanMap.values());
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public List<AuthenticationStatusScanner> getActiveScans() {
        List<AuthenticationStatusScanner> list = new ArrayList<AuthenticationStatusScanner>();
        authenticationStatusScansLock.lock();
        try {
            for (AuthenticationStatusScanner scan : authenticationStatusScanMap.values()) {
                if (!scan.isStopped()) {
                    list.add(scan);
                }
            }
            return list;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public AuthenticationStatusScanner getScan(int id) {
        authenticationStatusScansLock.lock();
        try {
            return this.authenticationStatusScanMap.get(id);
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void stopScan(int id) {
        authenticationStatusScansLock.lock();
        try {
            if (this.authenticationStatusScanMap.containsKey(id)) {
                this.authenticationStatusScanMap.get(id).stopScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void stopAllScans() {
        authenticationStatusScansLock.lock();
        try {
            for (AuthenticationStatusScanner scan : authenticationStatusScanMap.values()) {
                scan.stopScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void pauseScan(int id) {
        authenticationStatusScansLock.lock();
        try {
            if (this.authenticationStatusScanMap.containsKey(id)) {
                this.authenticationStatusScanMap.get(id).pauseScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void pauseAllScans() {
        authenticationStatusScansLock.lock();
        try {
            for (AuthenticationStatusScanner scan : authenticationStatusScanMap.values()) {
                scan.pauseScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void resumeScan(int id) {
        authenticationStatusScansLock.lock();
        try {
            if (this.authenticationStatusScanMap.containsKey(id)) {
                this.authenticationStatusScanMap.get(id).resumeScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public void resumeAllScans() {
        authenticationStatusScansLock.lock();
        try {
            for (AuthenticationStatusScanner scan : authenticationStatusScanMap.values()) {
                scan.resumeScan();
            }
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public AuthenticationStatusScanner removeScan(int id) {
        authenticationStatusScansLock.lock();

        try {
            if (!authenticationStatusScanMap.containsKey(id)) {
                throw new IllegalArgumentException("No scan found for given id: " + id);
            }
            AuthenticationStatusScanner authenticationStatusScan =
                    this.authenticationStatusScanMap.get(id);
            authenticationStatusScan.stopScan();
            authenticationStatusScanMap.remove(id);
            return authenticationStatusScan;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public int removeAllScans() {
        authenticationStatusScansLock.lock();
        try {
            int count = 0;
            for (Iterator<AuthenticationStatusScanner> it =
                            authenticationStatusScanMap.values().iterator();
                    it.hasNext(); ) {
                AuthenticationStatusScanner authenticationStatusScan = it.next();
                authenticationStatusScan.stopScan();
                it.remove();
                count++;
            }
            return count;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Override
    public int removeFinishedScans() {
        authenticationStatusScansLock.lock();
        try {
            int count = 0;
            for (Iterator<AuthenticationStatusScanner> it =
                            authenticationStatusScanMap.values().iterator();
                    it.hasNext(); ) {
                AuthenticationStatusScanner authenticationStatusScan = it.next();
                if (authenticationStatusScan.isStopped()) {
                    authenticationStatusScan.stopScan();
                    it.remove();
                    count++;
                }
            }
            return count;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }

    @Deprecated
    @Override
    public AuthenticationStatusScanner getLastScan() {
        return null;
    }

    public void reset() {
        this.removeAllScans();
        authenticationStatusScansLock.lock();
        try {
            this.scanIdCounter = 0;
        } finally {
            authenticationStatusScansLock.unlock();
        }
    }
}
