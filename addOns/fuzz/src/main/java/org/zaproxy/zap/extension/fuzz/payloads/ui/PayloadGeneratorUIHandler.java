/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.ui;

import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;

public interface PayloadGeneratorUIHandler<
        T extends Payload, T2 extends PayloadGenerator<T>, T3 extends PayloadGeneratorUI<T, T2>> {

    String getName();

    Class<T3> getPayloadGeneratorUIClass();

    Class<? extends PayloadGeneratorUIPanel<T, T2, T3>> getPayloadGeneratorUIPanelClass();

    PayloadGeneratorUIPanel<T, T2, T3> createPanel();
}
