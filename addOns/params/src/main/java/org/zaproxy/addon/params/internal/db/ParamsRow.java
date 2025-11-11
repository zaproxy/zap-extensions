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
package org.zaproxy.addon.params.internal.db;

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
@PersistenceCapable(table = "PARAMS_PARAM", detachable = "true")
public class ParamsRow {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    @Column(name = "PARAMID")
    private long paramId;

    @Column(name = "SITE", length = 32768)
    private String site;

    @Column(name = "TYPE", length = 32768)
    private String type;

    @Column(name = "NAME", length = 32768)
    private String name;

    @Column(name = "USED")
    private int used;

    @Column(name = "FLAGS", length = 32768)
    private String flags;

    @Column(name = "VALS", length = 8388608)
    private String vals;
}
