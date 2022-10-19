/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

public abstract class OastService {

    private final List<OastRequestHandler> oastRequestHandlerList = new ArrayList<>();
    private final List<OastStateChangedListener> oastStateChangedListenerList = new ArrayList<>();

    public abstract String getName();

    /** Starts the OastService. This method should be called after ZAP has initialised. */
    public abstract void startService();

    public abstract void stopService();

    public abstract boolean isRegistered();

    /**
     * Always returns a new payload. Registers with the service if required.
     *
     * @return a new URL that can be used for external interaction requests, never {@code null}.
     * @throws Exception if it is unable to get a new payload.
     */
    public abstract String getNewPayload() throws Exception;

    public void poll() {}

    public void sessionChanged() {}

    public void addOastRequestHandler(OastRequestHandler oastRequestHandler) {
        oastRequestHandlerList.add(oastRequestHandler);
    }

    public void removeOastRequestHandler(OastRequestHandler oastRequestHandler) {
        oastRequestHandlerList.remove(oastRequestHandler);
    }

    public void handleOastRequest(OastRequest oastRequest) {
        for (OastRequestHandler handler : oastRequestHandlerList) {
            handler.handle(oastRequest);
        }
    }

    public void clearOastRequestHandlers() {
        oastRequestHandlerList.clear();
    }

    public void addOastStateChangedListener(OastStateChangedListener oastStateChangedListener) {
        oastStateChangedListenerList.add(oastStateChangedListener);
    }

    public void fireOastStateChanged() {
        fireOastStateChanged(new OastState(getName(), isRegistered(), null));
    }

    public void fireOastStateChanged(OastState oastState) {
        for (OastStateChangedListener handler : oastStateChangedListenerList) {
            handler.stateChanged(oastState);
        }
    }

    public void clearOastStateChangedListeners() {
        oastStateChangedListenerList.clear();
    }

    protected static class OastThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public OastThreadFactory(String namePrefix) {
            threadNumber = new AtomicInteger(1);
            this.namePrefix = namePrefix;
            group = Thread.currentThread().getThreadGroup();
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }
}
