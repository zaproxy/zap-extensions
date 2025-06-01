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
package org.zaproxy.zap.extension.scripts.scanrules;

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public abstract class PassiveScriptHelper extends PluginPassiveScanner {

    @Override
    public AlertBuilder newAlert() {
        return super.newAlert();
    }

    @Override
    public void addHistoryTag(String tag) {
        super.addHistoryTag(tag);
    }

    /**
     * @deprecated Use {@link #newAlert()} to build and {@link AlertBuilder#raise() raise} alerts.
     */
    @Deprecated
    public void raiseAlert(
            int risk,
            int confidence,
            String name,
            String description,
            String uri,
            String param,
            String attack,
            String otherInfo,
            String solution,
            String evidence,
            int cweId,
            int wascId,
            HttpMessage msg) {

        raiseAlert(
                risk,
                confidence,
                name,
                description,
                uri,
                param,
                attack,
                otherInfo,
                solution,
                evidence,
                null,
                cweId,
                wascId,
                msg);
    }

    /**
     * @deprecated Use {@link #newAlert()} to build and {@link AlertBuilder#raise() raise} alerts.
     */
    @Deprecated
    public void raiseAlert(
            int risk,
            int confidence,
            String name,
            String description,
            String uri,
            String param,
            String attack,
            String otherInfo,
            String solution,
            String evidence,
            String reference,
            int cweId,
            int wascId,
            HttpMessage msg) {

        newAlert()
                .setRisk(risk)
                .setConfidence(confidence)
                .setName(name)
                .setDescription(description)
                .setParam(param)
                .setOtherInfo(otherInfo)
                .setSolution(solution)
                .setReference(reference)
                .setEvidence(evidence)
                .setCweId(cweId)
                .setWascId(wascId)
                .setMessage(msg)
                .raise();
    }

    /**
     * @deprecated Replaced by {@link #addHistoryTag(String)}
     */
    @Override
    @Deprecated
    public void addTag(String tag) {
        super.addHistoryTag(tag);
    }
}
