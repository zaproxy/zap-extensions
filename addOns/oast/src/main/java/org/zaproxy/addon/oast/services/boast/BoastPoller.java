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
package org.zaproxy.addon.oast.services.boast;

import java.time.LocalDateTime;
import java.util.Collection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.addon.oast.OastState;

public class BoastPoller implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger(BoastPoller.class);
    private final BoastService boastService;

    public BoastPoller(BoastService boastService) {
        this.boastService = boastService;
    }

    @Override
    public void run() {
        if (boastService.getRegisteredServers().isEmpty()) {
            return;
        }
        LOGGER.debug("Polling all registered BOAST Servers.");
        this.boastService.getRegisteredServers().stream()
                .map(BoastServer::poll)
                .flatMap(Collection::stream)
                .forEach(this::handleBoastEvent);
        this.boastService.fireOastStateChanged(
                new OastState(boastService.getName(), true, LocalDateTime.now()));
    }

    private void handleBoastEvent(BoastEvent boastEvent) {
        try {
            OastRequest oastRequest = boastEvent.toOastRequest();
            boastService.handleOastRequest(oastRequest);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn(
                    Constant.messages.getString("oast.boast.error.persist"),
                    boastEvent.getDump(),
                    e);
        }
    }
}
