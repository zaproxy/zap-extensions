/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.db;

import java.time.Instant;
import javax.jdo.annotations.Cacheable;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Cacheable("false")
@PersistenceCapable(table = "AUTHHELPER_DIAGNOSTIC_BROWSER_STORAGE_ITEM", detachable = "true")
public class DiagnosticBrowserStorageItem {

    private static final String STORAGE_SCRIPT =
            """
            const data = [];
            for (let i = 0; i < STORAGE.length; i++) {
                data.push({"key": STORAGE.key(i), "value": STORAGE.getItem(STORAGE.key(i))});
            }
            return data;
            """;

    public enum Type {
        LOCAL(STORAGE_SCRIPT.replace("STORAGE", "window.localStorage")),
        SESSION(STORAGE_SCRIPT.replace("STORAGE", "sessionStorage"));

        private String script;

        Type(String script) {
            this.script = script;
        }

        public String getScript() {
            return script;
        }
    }

    private Instant createTimestamp;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private int id;

    @Column(name = "STEPID", allowsNull = "false")
    private DiagnosticStep step;

    @Column(jdbcType = "INTEGER")
    private Type type;

    @Column(length = 4096)
    private String key;

    @Column(length = 65536)
    private String value;
}
