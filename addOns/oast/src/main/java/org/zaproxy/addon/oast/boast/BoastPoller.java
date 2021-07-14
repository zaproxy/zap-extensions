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
package org.zaproxy.addon.oast.boast;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import net.sf.json.JSONObject;

public class BoastPoller {

    private final List<PollerThread> pollerThreadList = new ArrayList<>();

    public void startPolling(JSONObject registeredServer) {
        String boastId = registeredServer.getString("id");
        String boastCanary = registeredServer.getString("canary");
        PollerThread pollerThread =
                new PollerThread("BOAST-Poller-" + boastId) {
                    @Override
                    public void run() {
                        return;
                    }
                };
    }

    private static class PollerThread extends Thread {

        private final AtomicBoolean running = new AtomicBoolean(false);

        public PollerThread(String name) {
            super(name);
        }

        public void startThread() {
            running.set(true);
            start();
        }

        public void stopThread() {
            interrupt();
            running.set(false);
        }

        protected boolean isRunning() {
            return running.get();
        }
    }
}
