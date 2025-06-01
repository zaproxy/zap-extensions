/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client.impl;

/**
 * This interface defines the contract for a client-side extension handling Zest statements. Zest
 * statements represent specific actions or operations to be performed by the Add-on.
 *
 * <p>Note: This interface is not intended to be implemented or used by other add-ons.
 */
public interface ClientZestRecorder {

    /**
     * Adds a Zest statement to the client's Zest statement utility.
     *
     * @param stmt the stringified JSON object representing the Zest statement to be added.
     * @throws Exception if an error occurs while adding the Zest statement.
     */
    void addZestStatement(String stmt) throws Exception;
}
