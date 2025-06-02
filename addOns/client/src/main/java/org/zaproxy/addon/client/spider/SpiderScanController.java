/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ScanController;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

public class SpiderScanController implements ScanController<ClientSpider> {

    private static final Logger LOGGER = LogManager.getLogger(SpiderScanController.class);

    private ExtensionClientIntegration extension;

    private final ValueProvider valueProvider;

    /**
     * The {@code Lock} for exclusive access of instance variables related to multiple active scans.
     *
     * @see #clientSpiderMap
     * @see #scanIdCounter
     */
    private final Lock clientSpidersLock;

    /**
     * The counter used to give an unique ID to active scans.
     *
     * <p><strong>Note:</strong> All accesses (both write and read) should be done while holding the
     * {@code Lock} {@code clientSpidersLock}.
     *
     * @see #clientSpidersLock
     * @see #startScan(String, Target, User, Object[])
     */
    private int scanIdCounter;

    /**
     * A map that contains all {@code ClientSpider}s created (and not yet removed). Used to control
     * (i.e. pause/resume and stop) the multiple active scans and get its results. The instance
     * variable is never {@code null}. The map key is the ID of the scan.
     *
     * <p><strong>Note:</strong> All accesses (both write and read) should be done while holding the
     * {@code Lock} {@code clientSpidersLock}.
     *
     * @see #clientSpidersLock
     * @see #startScan(String, Target, User, Object[])
     * @see #scanIdCounter
     */
    private Map<Integer, ClientSpider> clientSpiderMap;

    /**
     * An ordered list of all of the {@code ClientSpider}s created (and not yet removed). Used to
     * get provide the 'last' scan for client using the 'old' API that didn't support concurrent
     * scans.
     */
    private List<ClientSpider> clientSpiderList;

    public SpiderScanController(ExtensionClientIntegration extension, ValueProvider valueProvider) {
        this.clientSpidersLock = new ReentrantLock();
        this.extension = extension;
        this.valueProvider = valueProvider;
        this.clientSpiderMap = new HashMap<>();
        this.clientSpiderList = new ArrayList<>();
    }

    @Override
    public int startScan(String name, Target target, User user, Object[] contextSpecificObjects) {
        clientSpidersLock.lock();
        try {
            int id = this.scanIdCounter++;

            ClientOptions clientOptions = extension.getClientParam();
            URI startUri = null;
            boolean subtreeOnly = false;
            Context context = null;

            if (contextSpecificObjects != null) {
                for (Object obj : contextSpecificObjects) {
                    if (obj == null) {
                        continue;
                    }

                    if (obj instanceof ClientOptions) {
                        LOGGER.debug("Setting custom spider params");
                        clientOptions = (ClientOptions) obj;
                    } else if (obj instanceof URI) {
                        startUri = (URI) obj;
                    } else if (obj instanceof Context) {
                        context = (Context) obj;
                    } else if (obj instanceof Boolean) {
                        subtreeOnly = (Boolean) obj;
                    } else {
                        LOGGER.error(
                                "Unexpected contextSpecificObject: {}",
                                obj.getClass().getCanonicalName());
                    }
                }
            }

            ClientSpider scan =
                    new ClientSpider(
                            extension,
                            name,
                            startUri.toString(),
                            clientOptions,
                            id,
                            context,
                            user,
                            subtreeOnly,
                            valueProvider);

            this.clientSpiderMap.put(id, scan);
            this.clientSpiderList.add(scan);
            scan.run();

            return id;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public ClientSpider getScan(int id) {
        return this.clientSpiderMap.get(id);
    }

    @Override
    public ClientSpider getLastScan() {
        clientSpidersLock.lock();
        try {
            if (clientSpiderList.isEmpty()) {
                return null;
            }
            return clientSpiderList.get(clientSpiderList.size() - 1);
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public List<ClientSpider> getAllScans() {
        List<ClientSpider> list = new ArrayList<>();
        clientSpidersLock.lock();
        try {
            for (ClientSpider scan : clientSpiderList) {
                list.add(scan);
            }
            return list;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public List<ClientSpider> getActiveScans() {
        List<ClientSpider> list = new ArrayList<>();
        clientSpidersLock.lock();
        try {
            for (ClientSpider scan : clientSpiderList) {
                if (!scan.isStopped()) {
                    list.add(scan);
                }
            }
            return list;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public ClientSpider removeScan(int id) {
        clientSpidersLock.lock();

        try {
            ClientSpider ascan = this.clientSpiderMap.get(id);
            if (!clientSpiderMap.containsKey(id)) {
                return null;
            }
            removeScanImpl(ascan);
            clientSpiderMap.remove(id);
            return ascan;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    public int getTotalNumberScans() {
        return clientSpiderMap.size();
    }

    @Override
    public void stopAllScans() {
        clientSpidersLock.lock();
        try {
            for (ClientSpider scan : clientSpiderMap.values()) {
                scan.stopScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public void pauseAllScans() {
        clientSpidersLock.lock();
        try {
            for (ClientSpider scan : clientSpiderMap.values()) {
                scan.pauseScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public void resumeAllScans() {
        clientSpidersLock.lock();
        try {
            for (ClientSpider scan : clientSpiderMap.values()) {
                scan.resumeScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public int removeAllScans() {
        clientSpidersLock.lock();
        try {
            int count = 0;
            for (Iterator<ClientSpider> it = clientSpiderMap.values().iterator(); it.hasNext(); ) {
                ClientSpider ascan = it.next();
                removeScanImpl(ascan);
                it.remove();
                count++;
            }
            return count;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    private void removeScanImpl(ClientSpider scan) {
        scan.stopScan();
        scan.unload();
        clientSpiderList.remove(scan);
    }

    @Override
    public int removeFinishedScans() {
        clientSpidersLock.lock();
        try {
            int count = 0;
            for (Iterator<ClientSpider> it = clientSpiderMap.values().iterator(); it.hasNext(); ) {
                ClientSpider scan = it.next();
                if (scan.isStopped()) {
                    removeScanImpl(scan);
                    it.remove();
                    count++;
                }
            }
            return count;
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public void stopScan(int id) {
        clientSpidersLock.lock();
        try {
            if (this.clientSpiderMap.containsKey(id)) {
                this.clientSpiderMap.get(id).stopScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public void pauseScan(int id) {
        clientSpidersLock.lock();
        try {
            if (this.clientSpiderMap.containsKey(id)) {
                this.clientSpiderMap.get(id).pauseScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    @Override
    public void resumeScan(int id) {
        clientSpidersLock.lock();
        try {
            if (this.clientSpiderMap.containsKey(id)) {
                this.clientSpiderMap.get(id).resumeScan();
            }
        } finally {
            clientSpidersLock.unlock();
        }
    }

    public void reset() {
        this.removeAllScans();
        clientSpidersLock.lock();
        try {
            this.scanIdCounter = 0;
        } finally {
            clientSpidersLock.unlock();
        }
    }
}
