/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.internal.db;

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
@PersistenceCapable(table = "CLIENT_HISTORY", detachable = "true")
public class ClientHistoryEntry {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private long id;

    private Instant timestamp;

    private String type;

    private int objectType;

    @Column(length = 1024)
    private String tagName;

    @Column(length = 1024)
    private String elementId;

    @Column(length = 4096)
    private String nodeName;

    @Column(length = 8192)
    private String url;

    @Column(length = 8192)
    private String xpath;

    @Column(length = 8192)
    private String href;

    @Column(length = 8192)
    private String text;

    @Column(length = 256)
    private String tagType;

    private Integer formId;

    private Integer count;
}
