/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.addon.requester.internal.tab.editor;

import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.zaproxy.addon.requester.db.RequesterTabRecord;
import org.zaproxy.addon.requester.db.RequesterTabStorage;
import org.zaproxy.addon.requester.internal.ManualHttpRequestEditorPanel;
import org.zaproxy.addon.requester.util.RequesterMessageConverter;
import org.zaproxy.zap.extension.httppanel.Message;

import java.io.IOException;

/**
 * Wraps {@link ManualHttpRequestEditorPanel} in order to update tabStorage when appropriate methods gets called.
 */
@Setter
@RequiredArgsConstructor
public class RequestTabHttpEditorWrapper extends ManualHttpRequestEditorPanel {

    private static final long serialVersionUID = 1L;

    private final RequesterTabStorage tabStorage;
    private final RequesterTabRecord tabRecord;

    /**
     * Should messages be updated?
     * <p>(prevents updating messages during first load and unload)</p>
     */
    private boolean updateTabRecord = true;

    @Override
    public void setMessage(Message message) {
        super.setMessage(message);

        updateTabRecordIfNeeded(message);
    }

    @Override
    protected void sendMessage(Message message) throws IOException {
        super.sendMessage(message);

        updateTabRecordIfNeeded(message);
    }

    @Override
    public void unload() {
        updateTabRecord = false;
        super.unload();
    }

    private void updateTabRecordIfNeeded(Message message) {
        if (!updateTabRecord) {
            return;
        }

        tabRecord.setMessage(RequesterMessageConverter.toJsonObject(message));
        tabStorage.updateTabMessage(tabRecord);
    }

}