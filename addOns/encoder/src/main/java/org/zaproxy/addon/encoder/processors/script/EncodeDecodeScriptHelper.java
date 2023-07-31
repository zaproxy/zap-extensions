/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.script;

import org.parosproxy.paros.Constant;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessorItem;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessors;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;
import org.zaproxy.addon.encoder.processors.predefined.DefaultEncodeDecodeProcessor;

public class EncodeDecodeScriptHelper {

    private static final EncodeDecodeScriptHelper INSTANCE = new EncodeDecodeScriptHelper();

    public static EncodeDecodeScriptHelper getSingleton() {
        return INSTANCE;
    }

    /**
     * Returns the processor with the given identified, or a default processor which will state the
     * sought one was not found.
     *
     * @param id of the processor to be returned.
     * @return the {@code EncodeDecodeProcessor} which was requested, or a default processor.
     */
    public EncodeDecodeProcessor getProcessorById(String id) {
        for (EncodeDecodeProcessorItem item : EncodeDecodeProcessors.getPredefinedProcessors()) {
            if (item.getId().equalsIgnoreCase(EncodeDecodeProcessors.PREDEFINED_PREFIX + id)) {
                return item.getProcessor();
            }
        }
        return getDefaultProcessor(id);
    }

    private DefaultEncodeDecodeProcessor getDefaultProcessor(String id) {
        return new DefaultEncodeDecodeProcessor() {
            @Override
            protected String processInternal(String value) throws Exception {
                return Constant.messages.getString("encoder.scripts.helper.processor.fallback", id);
            }
        };
    }

    /**
     * Creates an {@code EncodeDecodeResult} object setting the result value.
     *
     * @param value the processor output to be returned.
     * @return the {@code EncodeDecodeResult} with the given value.
     */
    public EncodeDecodeResult newResult(String value) {
        return new EncodeDecodeResult(value);
    }

    /**
     * Creates an {@code EncodeDecodeResult} object setting the error.
     *
     * @param error the result to be set.
     * @return the {@Code EncodeDecodeResult} with the given error.
     */
    public EncodeDecodeResult newError(String error) {
        return EncodeDecodeResult.withError(error);
    }
}
