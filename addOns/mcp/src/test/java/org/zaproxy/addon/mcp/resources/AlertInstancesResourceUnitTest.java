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
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.zaproxy.zap.extension.alert.AlertParam;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link AlertInstancesResource}. */
class AlertInstancesResourceUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ExtensionLoader extensionLoader;
    private ExtensionAlert extAlert;
    private AlertParam alertParam;
    private TableAlert tableAlert;
    private AlertInstancesResource resource;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAlert = mock(ExtensionAlert.class, withSettings().strictness(Strictness.LENIENT));
        alertParam = mock(AlertParam.class, withSettings().strictness(Strictness.LENIENT));
        tableAlert = mock(TableAlert.class, withSettings().strictness(Strictness.LENIENT));

        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(extAlert);
        // 0 = unlimited in AlertParam → resource falls back to DEFAULT_PAGE_SIZE
        given(extAlert.getAlertParam()).willReturn(alertParam);
        given(alertParam.getMaximumInstances()).willReturn(0);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Database db = mock(Database.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getDb()).willReturn(db);
        given(db.getTableAlert()).willReturn(tableAlert);

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);
        resource = new AlertInstancesResource();
    }

    // -------------------------------------------------------------------------
    // Metadata
    // -------------------------------------------------------------------------

    @Test
    void shouldHaveCorrectUriAndName() {
        assertThat(resource.getUri(), equalTo("zap://alerts/"));
        assertThat(resource.getName(), equalTo("alert-instances"));
    }

    // -------------------------------------------------------------------------
    // Input validation
    // -------------------------------------------------------------------------

    @Test
    void shouldReturnErrorForInvalidUri() {
        String content = resource.readContent("zap://other/100-1");
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.invaliduri!\"}"));
    }

    @Test
    void shouldReturnErrorForMissingAlertRef() {
        String content = resource.readContent("zap://alerts/");
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.missingalertref!\"}"));
    }

    @Test
    void shouldReturnErrorForNegativeStart() {
        String content = resource.readContent("zap://alerts/100-1?start=-1");
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.negativestart!\"}"));
    }

    @Test
    void shouldReturnErrorForNonIntegerStart() {
        String content = resource.readContent("zap://alerts/100-1?start=abc");
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.invalidstart!\"}"));
    }

    @Test
    void shouldReturnErrorForNonIntegerCount() {
        String content = resource.readContent("zap://alerts/100-1?count=abc");
        assertThat(
                content,
                equalTo("{\"error\":\"!mcp.resource.alertinstances.error.invalidcount!\"}"));
    }

    // -------------------------------------------------------------------------
    // No extension / no data
    // -------------------------------------------------------------------------

    @Test
    void shouldReturnEmptyArrayWhenExtensionAlertNotInstalled() {
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(null);
        String content = resource.readContent("zap://alerts/100-1");
        assertThat(content, equalTo("[]"));
    }

    @Test
    void shouldReturnZeroCountWhenNoAlerts() throws Exception {
        given(tableAlert.getAlertList()).willReturn(new Vector<>());

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));
        assertThat(root.get("totalCount").intValue(), is(0));
        assertThat(root.get("returnedCount").intValue(), is(0));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.get("instances").size(), is(0));
    }

    @Test
    void shouldReturnZeroCountWhenNoMatchingAlertRef() throws Exception {
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/200-1"));
        assertThat(root.get("totalCount").intValue(), is(0));
        assertThat(root.get("returnedCount").intValue(), is(0));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.get("instances").size(), is(0));
    }

    // -------------------------------------------------------------------------
    // Basic single-page response shape
    // -------------------------------------------------------------------------

    @Test
    void shouldReturnInstanceWithCorrectFields() throws Exception {
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));

        assertThat(root.get("alertRef").textValue(), equalTo("100-1"));
        assertThat(root.get("totalCount").intValue(), is(1));
        assertThat(root.get("start").intValue(), is(0));
        assertThat(root.get("returnedCount").intValue(), is(1));
        assertThat(root.get("truncated").booleanValue(), is(false));

        JsonNode instance = root.get("instances").get(0);
        assertThat(instance.get("name").textValue(), equalTo("XSS"));
        assertThat(instance.get("risk").textValue(), equalTo("High"));
        assertThat(instance.get("confidence").textValue(), equalTo("Medium"));
        assertThat(instance.get("pluginId").intValue(), is(100));
        assertThat(instance.get("alertRef").textValue(), equalTo("100-1"));
        assertThat(instance.get("systemic").booleanValue(), is(false));
    }

    @Test
    void shouldReturnOnlyMatchingInstances() throws Exception {
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

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));

        assertThat(root.get("totalCount").intValue(), is(2));
        assertThat(root.get("returnedCount").intValue(), is(2));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.get("instances").size(), is(2));
    }

    // -------------------------------------------------------------------------
    // Truncation: response is bounded at DEFAULT_PAGE_SIZE
    // -------------------------------------------------------------------------

    @Test
    void shouldTruncateAtDefaultPageSizeAndSetTruncatedFlag() throws Exception {
        // Create DEFAULT_PAGE_SIZE + 1 matching alerts
        int total = AlertInstancesResource.DEFAULT_PAGE_SIZE + 1;
        Vector<Integer> ids = new Vector<>();
        for (int i = 1; i <= total; i++) {
            ids.add(i);
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList()).willReturn(ids);

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));

        assertThat(root.get("totalCount").intValue(), is(total));
        assertThat(root.get("returnedCount").intValue(), is(AlertInstancesResource.DEFAULT_PAGE_SIZE));
        assertThat(root.get("truncated").booleanValue(), is(true));
        assertThat(root.has("nextPageUri"), is(true));
        assertThat(root.has("note"), is(true));
        assertThat(root.get("instances").size(), is(AlertInstancesResource.DEFAULT_PAGE_SIZE));
    }

    @Test
    void shouldNotTruncateWhenCountEqualsDefaultPageSize() throws Exception {
        int total = AlertInstancesResource.DEFAULT_PAGE_SIZE;
        Vector<Integer> ids = new Vector<>();
        for (int i = 1; i <= total; i++) {
            ids.add(i);
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList()).willReturn(ids);

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));

        assertThat(root.get("totalCount").intValue(), is(total));
        assertThat(root.get("returnedCount").intValue(), is(total));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.has("nextPageUri"), is(false));
    }

    // -------------------------------------------------------------------------
    // Pagination: ?start=N&count=M
    // -------------------------------------------------------------------------

    @Test
    void shouldReturnSecondPageWhenStartIsSpecified() throws Exception {
        // 5 alerts total, request page 2 (start=3, count=2)
        for (int i = 1; i <= 5; i++) {
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS-" + i);
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1, 2, 3, 4, 5)));

        JsonNode root =
                MAPPER.readTree(resource.readContent("zap://alerts/100-1?start=3&count=2"));

        assertThat(root.get("totalCount").intValue(), is(5));
        assertThat(root.get("start").intValue(), is(3));
        assertThat(root.get("returnedCount").intValue(), is(2));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.get("instances").size(), is(2));
    }

    @Test
    void shouldReturnNextPageUriWhenMorePagesExist() throws Exception {
        // 10 alerts, request first 3
        for (int i = 1; i <= 10; i++) {
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList())
                .willReturn(new Vector<>(List.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)));

        JsonNode root =
                MAPPER.readTree(resource.readContent("zap://alerts/100-1?start=0&count=3"));

        assertThat(root.get("truncated").booleanValue(), is(true));
        assertThat(
                root.get("nextPageUri").textValue(),
                equalTo("zap://alerts/100-1?start=3&count=3"));
    }

    @Test
    void shouldCapCountAtMaxPageSize() throws Exception {
        // Request count far above MAX_PAGE_SIZE — should be capped
        int total = AlertInstancesResource.MAX_PAGE_SIZE + 10;
        Vector<Integer> ids = new Vector<>();
        for (int i = 1; i <= total; i++) {
            ids.add(i);
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList()).willReturn(ids);

        JsonNode root =
                MAPPER.readTree(
                        resource.readContent(
                                "zap://alerts/100-1?count=" + (AlertInstancesResource.MAX_PAGE_SIZE + 50)));

        assertThat(root.get("returnedCount").intValue(), is(AlertInstancesResource.MAX_PAGE_SIZE));
        assertThat(root.get("truncated").booleanValue(), is(true));
    }

    @Test
    void shouldReturnEmptyPageWhenStartBeyondTotal() throws Exception {
        RecordAlert rec =
                mockRecordAlert(1, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1)));
        given(tableAlert.read(1)).willReturn(rec);

        JsonNode root =
                MAPPER.readTree(resource.readContent("zap://alerts/100-1?start=99&count=10"));

        assertThat(root.get("totalCount").intValue(), is(1));
        assertThat(root.get("returnedCount").intValue(), is(0));
        assertThat(root.get("truncated").booleanValue(), is(false));
        assertThat(root.get("instances").size(), is(0));
    }

    // -------------------------------------------------------------------------
    // AlertParam.getMaximumInstances() integration
    // -------------------------------------------------------------------------

    @Test
    void shouldRespectAlertParamMaximumInstancesWhenTighter() throws Exception {
        // AlertParam caps at 2, which is tighter than DEFAULT_PAGE_SIZE
        given(alertParam.getMaximumInstances()).willReturn(2);

        for (int i = 1; i <= 5; i++) {
            RecordAlert rec =
                    mockRecordAlert(
                            i, 100, "100-1", Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "XSS");
            given(tableAlert.read(i)).willReturn(rec);
        }
        given(tableAlert.getAlertList()).willReturn(new Vector<>(List.of(1, 2, 3, 4, 5)));

        JsonNode root = MAPPER.readTree(resource.readContent("zap://alerts/100-1"));

        assertThat(root.get("returnedCount").intValue(), is(2));
        assertThat(root.get("totalCount").intValue(), is(5));
        assertThat(root.get("truncated").booleanValue(), is(true));
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

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
