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

import java.io.IOException;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;

public abstract class ActiveScriptHelper extends AbstractAppParamPlugin {

    @Override
    public boolean isStop() {
        return super.isStop();
    }

    public String setParam(HttpMessage msg, String param, String value) {
        return super.setParameter(msg, param, value);
    }

    public String setEscapedParam(HttpMessage msg, String param, String value) {
        return super.setEscapedParameter(msg, param, value);
    }

    @Override
    public void sendAndReceive(HttpMessage msg) throws IOException {
        super.sendAndReceive(msg);
    }

    @Override
    public void sendAndReceive(HttpMessage msg, boolean isFollowRedirect) throws IOException {
        super.sendAndReceive(msg, isFollowRedirect);
    }

    @Override
    public void sendAndReceive(HttpMessage msg, boolean isFollowRedirect, boolean handleAntiCSRF)
            throws IOException {
        super.sendAndReceive(msg, isFollowRedirect, handleAntiCSRF);
    }

    @Override
    public AlertBuilder newAlert() {
        return super.newAlert();
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
        super.bingo(
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
        super.bingo(
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
                reference,
                cweId,
                wascId,
                msg);
    }

    @Override
    public boolean isPage200(HttpMessage msg) {
        return super.isPage200(msg);
    }

    @Override
    public boolean isPage404(HttpMessage msg) {
        return super.isPage404(msg);
    }

    @Override
    public boolean isPage500(HttpMessage msg) {
        return super.isPage500(msg);
    }

    @Override
    public boolean isPageOther(HttpMessage msg) {
        return super.isPageOther(msg);
    }
}
