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
package org.zaproxy.addon.mcp.resources;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import java.util.Locale;
import java.util.Vector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link AlertInstancesResource}. */
class AlertInstancesResourceUnitTest {

    private ExtensionLoader extensionLoader;
    private ExtensionAlert extAlert;
    private TableAlert tableAlert;
    private AlertInstancesResource resource;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAlert = mock(ExtensionAlert.class, withSettings().strictness(Strictness.LENIENT));
        tableAlert = mock(TableAlert.class, withSettings().strictness(Strictness.LENIENT));

        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(extAlert);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Database db = mock(Database.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getDb()).willReturn(db);
        given(db.getTableAlert()).willReturn(tableAlert);

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);
        resource = new AlertInstancesResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://alerts/"));
        assertThat(resource.getName(), equalTo("alert-instances"));
    }

    @Test
    void shouldReturnErrorForInvalidUri() {
        // Given / When
        String content = resource.readContent("zap://other/100-1");

        // Then
        assertThat(
                content, equalTo("{\"error\":\"!mcp.resource.alertinstances.error.invaliduri!\"}"));
    }

    @Test
    void shouldReturnErrorForMissingAlertRef() {
        // Given / When
        String content = resource.readContent("zap://alerts/");

        // Then
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.missingalertref!\"}"));
    }

    @Test
    void shouldReturnEmptyArrayWhenExtensionAlertNotInstalled() {
        // Given
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(null);

        // When
        String content = resource.readContent("zap://alerts/100-1");

        // Then
        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnInstancesWithRiskAndConfidenceAsStrings() throws Exception {
        // Given
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        // When
        String content = resource.readContent("zap://alerts/100-1");

        // Then
        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"XSS\","
                                + "\"description\":\"\","
                                + "\"solution\":\"\","
                                + "\"risk\":\"High\","
                                + "\"confidence\":\"Medium\","
                                + "\"uri\":\"\","
                                + "\"param\":\"\","
                                + "\"attack\":\"\","
                                + "\"evidence\":\"\","
                                + "\"other\":\"\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false}]"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoMatchingAlertRef() throws Exception {
        // Given
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        // When
        String content = resource.readContent("zap://alerts/200-1");

        // Then
        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnOnlyMatchingInstances() throws Exception {
        // Given
        RecordAlert rec1 =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        RecordAlert rec2 =
                mockRecordAlert(2, 200, "200-1", Alert.RISK_LOW, Alert.CONFIDENCE_LOW, "Other");
        RecordAlert rec3 =
                mockRecordAlert(3, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1, 2, 3)));
        given(tableAlert.read(1)).willReturn(rec1);
        given(tableAlert.read(2)).willReturn(rec2);
        given(tableAlert.read(3)).willReturn(rec3);

        // When
        String content = resource.readContent("zap://alerts/100-1");

        // Then
        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"XSS\","
                                + "\"description\":\"\","
                                + "\"solution\":\"\","
                                + "\"risk\":\"High\","
                                + "\"confidence\":\"Medium\","
                                + "\"uri\":\"\","
                                + "\"param\":\"\","
                                + "\"attack\":\"\","
                                + "\"evidence\":\"\","
                                + "\"other\":\"\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false},"
                                + "{\"name\":\"XSS\","
                                + "\"description\":\"\","
                                + "\"solution\":\"\","
                                + "\"risk\":\"High\","
                                + "\"confidence\":\"Medium\","
                                + "\"uri\":\"\","
                                + "\"param\":\"\","
                                + "\"attack\":\"\","
                                + "\"evidence\":\"\","
                                + "\"other\":\"\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false}]"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoAlerts() throws Exception {
        // Given
        given(tableAlert.getAlertList()).willReturn(new Vector<>());

        // When
        String content = resource.readContent("zap://alerts/100-1");

        // Then
        assertThat(content, equalTo("[]"));
    }

    private static RecordAlert mockRecordAlert(
            int alertId, int pluginId, String alertRef, int risk, int confidence, String name) {
        RecordAlert rec = mock(RecordAlert.class, withSettings().strictness(Strictness.LENIENT));
        given(rec.getAlertId()).willReturn(alertId);
        given(rec.getPluginId()).willReturn(pluginId);
        given(rec.getAlertRef()).willReturn(alertRef);
        given(rec.getRisk()).willReturn(risk);
        given(rec.getConfidence()).willReturn(confidence);
        given(rec.getAlert()).willReturn(name);
        given(rec.getDescription()).willReturn("");
        given(rec.getSolution()).willReturn("");
        given(rec.getUri()).willReturn("");
        given(rec.getParam()).willReturn("");
        given(rec.getAttack()).willReturn("");
        given(rec.getOtherInfo()).willReturn("");
        given(rec.getReference()).willReturn("");
        given(rec.getEvidence()).willReturn("");
        return rec;
    }
}
