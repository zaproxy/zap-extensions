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
import java.util.ArrayList;
import java.util.List;
import javax.jdo.annotations.Cacheable;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Cacheable("false")
@PersistenceCapable(table = "AUTHHELPER_DIAGNOSTIC", detachable = "true")
public class Diagnostic {

    private Instant createTimestamp;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private int id;

    private String authenticationMethod;

    private String context;
    private String user;

    @Column(length = 4194304)
    private String script;

    @Column(length = 8388608)
    private String afPlan;

    @Order(column = "NUMBER")
    @Element(dependent = "true")
    @Persistent(mappedBy = "diagnostic")
    private List<DiagnosticStep> steps = new ArrayList<>();

    public Diagnostic(String authenticationMethod, String context, String user) {
        this.authenticationMethod = authenticationMethod;
        this.context = context;
        this.user = user;
    }
}
