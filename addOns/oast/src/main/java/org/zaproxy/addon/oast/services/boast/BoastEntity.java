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
package org.zaproxy.addon.oast.services.boast;

import java.sql.Timestamp;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.PrimaryKey;
import org.datanucleus.api.jdo.annotations.CreateTimestamp;
import org.zaproxy.addon.oast.OastEntity;

@PersistenceCapable
public class BoastEntity implements OastEntity {

    @PrimaryKey private String id;
    private String canary;
    private String secret;
    private String uri;

    @CreateTimestamp private Timestamp registeredTimestamp;

    public BoastEntity(String id, String canary, String secret, String uri) {
        this.id = id;
        this.canary = canary;
        this.secret = secret;
        this.uri = uri;
    }

    public static BoastEntity fromBoastServer(BoastServer server) {
        return new BoastEntity(
                server.getId(), server.getCanary(), server.getSecret(), server.getUri().toString());
    }

    public String getId() {
        return id;
    }

    public String getCanary() {
        return canary;
    }

    public String getSecret() {
        return secret;
    }

    public String getUri() {
        return uri;
    }

    public Timestamp getRegisteredTimestamp() {
        return registeredTimestamp;
    }
}
