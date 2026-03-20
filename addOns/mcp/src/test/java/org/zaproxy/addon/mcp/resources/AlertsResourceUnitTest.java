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
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link AlertsResource}. */
class AlertsResourceUnitTest {

    private ExtensionLoader extensionLoader;
    private TableAlert tableAlert;
    private AlertsResource resource;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        tableAlert = mock(TableAlert.class, withSettings().strictness(Strictness.LENIENT));

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Database db = mock(Database.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getDb()).willReturn(db);
        given(db.getTableAlert()).willReturn(tableAlert);

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);
        resource = new AlertsResource();
    }

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://alerts"));
        assertThat(resource.getName(), equalTo("alerts"));
    }

    @Test
    void shouldReturnEmptyArrayWhenNoAlerts() throws Exception {
        // Given
        given(tableAlert.getAlertList()).willReturn(new Vector<>());

        // When
        String content = resource.readContent();

        // Then
        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnSummaryWithRiskAsString() throws Exception {
        // Given
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        // When
        String content = resource.readContent();

        // Then
        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"XSS\","
                                + "\"risk\":\"High\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false,"
                                + "\"instanceCount\":1,"
                                + "\"instancesUri\":\"zap://alerts/100-1\"}]"));
    }

    @Test
    void shouldOrderAlertsByRiskHighestFirst() throws Exception {
        // Given
        RecordAlert low =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_LOW, Alert.CONFIDENCE_LOW, "Low");
        RecordAlert high =
                mockRecordAlert(2, 200, "200-1", Alert.RISK_HIGH, Alert.CONFIDENCE_HIGH, "High");
        RecordAlert medium =
                mockRecordAlert(
                        3, 300, "300-1", Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, "Medium");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1, 2, 3)));
        given(tableAlert.read(1)).willReturn(low);
        given(tableAlert.read(2)).willReturn(high);
        given(tableAlert.read(3)).willReturn(medium);

        // When
        String content = resource.readContent();

        // Then
        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"High\","
                                + "\"risk\":\"High\","
                                + "\"pluginId\":200,"
                                + "\"alertRef\":\"200-1\","
                                + "\"systemic\":false,"
                                + "\"instanceCount\":1,"
                                + "\"instancesUri\":\"zap://alerts/200-1\"},"
                                + "{\"name\":\"Medium\","
                                + "\"risk\":\"Medium\","
                                + "\"pluginId\":300,"
                                + "\"alertRef\":\"300-1\","
                                + "\"systemic\":false,"
                                + "\"instanceCount\":1,"
                                + "\"instancesUri\":\"zap://alerts/300-1\"},"
                                + "{\"name\":\"Low\","
                                + "\"risk\":\"Low\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false,"
                                + "\"instanceCount\":1,"
                                + "\"instancesUri\":\"zap://alerts/100-1\"}]"));
    }

    @Test
    void shouldGroupAlertsByAlertRef() throws Exception {
        // Given
        RecordAlert rec1 =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        RecordAlert rec2 =
                mockRecordAlert(2, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1, 2)));
        given(tableAlert.read(1)).willReturn(rec1);
        given(tableAlert.read(2)).willReturn(rec2);

        // When
        String content = resource.readContent();

        // Then
        assertThat(
                content,
                equalTo(
                        "[{\"name\":\"XSS\","
                                + "\"risk\":\"High\","
                                + "\"pluginId\":100,"
                                + "\"alertRef\":\"100-1\","
                                + "\"systemic\":false,"
                                + "\"instanceCount\":2,"
                                + "\"instancesUri\":\"zap://alerts/100-1\"}]"));
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
