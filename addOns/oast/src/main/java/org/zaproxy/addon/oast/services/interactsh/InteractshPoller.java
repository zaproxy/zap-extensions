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
package org.zaproxy.addon.oast.services.interactsh;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.oast.OastRequest;

public class InteractshPoller implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger(InteractshPoller.class);
    private final InteractshService interactshService;

    public InteractshPoller(InteractshService interactshService) {
        this.interactshService = interactshService;
    }

    @Override
    public void run() {
        LOGGER.debug("Polling the Interactsh Server.");
        this.interactshService.getInteractions().forEach(this::handleInteraction);
    }

    private void handleInteraction(InteractshEvent event) {
        try {
            OastRequest oastRequest = event.toOastRequest();
            interactshService.handleOastRequest(oastRequest);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist interaction.", e);
        }
    }
}
