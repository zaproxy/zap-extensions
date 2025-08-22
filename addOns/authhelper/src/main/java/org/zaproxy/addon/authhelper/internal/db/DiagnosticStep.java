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
import java.util.stream.Stream;
import javax.jdo.annotations.Cacheable;
import javax.jdo.annotations.Column;
import javax.jdo.annotations.Element;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Join;
import javax.jdo.annotations.Order;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Cacheable("false")
@PersistenceCapable(table = "AUTHHELPER_DIAGNOSTIC_STEP", detachable = "true")
public class DiagnosticStep {

    private Instant createTimestamp;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private int id;

    @Column(name = "DIAGNOSTICID", allowsNull = "false")
    private Diagnostic diagnostic;

    @Column(length = 4096)
    private String url;

    @Column(length = 4096)
    private String description;

    @Column(name = "WEBELEMENTID")
    private DiagnosticWebElement webElement;

    @Persistent(mappedBy = "step", dependent = "true")
    private DiagnosticScreenshot screenshot;

    @Order(column = "NUMBER")
    @Element(dependent = "true")
    @Persistent(mappedBy = "step")
    private List<DiagnosticMessage> messages = new ArrayList<>();

    @Persistent(table = "AUTHHELPER_DIAGNOSTIC_STEP_WEB_ELEMENTS")
    @Join(column = "STEPID")
    @Element(column = "WEBELEMENTID", dependent = "true")
    @Order(column = "NUMBER")
    private List<DiagnosticWebElement> webElements = new ArrayList<>();

    @Order(column = "NUMBER")
    @Element(dependent = "true")
    @Persistent(mappedBy = "step")
    private List<DiagnosticBrowserStorageItem> browserStorageItems = new ArrayList<>();

    public DiagnosticStep(String description) {
        this.description = description;
    }

    public Stream<DiagnosticBrowserStorageItem> getBrowserLocalStorage() {
        return getBrowerStorage(DiagnosticBrowserStorageItem.Type.LOCAL);
    }

    public Stream<DiagnosticBrowserStorageItem> getBrowserSessionStorage() {
        return getBrowerStorage(DiagnosticBrowserStorageItem.Type.SESSION);
    }

    private Stream<DiagnosticBrowserStorageItem> getBrowerStorage(
            DiagnosticBrowserStorageItem.Type type) {
        return browserStorageItems.stream().filter(e -> e.getType() == type);
    }
}
