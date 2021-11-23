/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;
import static org.zaproxy.addon.reports.TestAlertBuilder.newAlertBuilder;
import static org.zaproxy.addon.reports.TestAlertNodeBuilder.newAlertNodeBuilder;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.FileTemplateResolver;
import org.zaproxy.addon.automation.jobs.PassiveScanJobResultData;
import org.zaproxy.addon.reports.sarif.SarifReportDataSupport;
import org.zaproxy.addon.reports.sarif.SarifToolData;
import org.zaproxy.addon.reports.sarif.SarifToolData.SarifToolDataProvider;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * This integration test uses the real ZAP template engine to create a SARIF report output. Why an
 * integration test and not "normal" JUnit test? The {@link SarifReportDataSupport} creates an
 * adopted SARIF data structure/model and there are multiple objects necessary to provide an easy to
 * read report template file. So we test multiple objects here which we do not all want to mock -
 * also it gave the the chance to develop the SARIF report parts without always starting ZAP UI. So
 * test data is much more detailed as normally expected to simulate a real world scenario.
 */
class SarifReportIntegrationTest {

    private static final String FINDING_1_URI =
            "https://127.0.0.1:8080/greeting?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E";
    private static final String FINDING_2_URI =
            "https://127.0.0.1:8080/greeting2?name=%3C%2Fp%3E%3Cscript%3Ealert%281%29%3B%3C%2Fscript%3E%3Cp%3E";
    private Template template;
    private TemplateEngine templateEngine;

    @BeforeEach
    void setUp() throws Exception {
        /* setup ZAP for testing - necessary dependencies for report data creation */
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        Constant.PROGRAM_VERSION = "Dev Build";
    }

    @Test
    void templateEngineCanProcessSarifJsonReportAndOutputIsAsExpected() throws Exception {
        /* prepare */
        configureTemplateEngine("sarif-json");

        ReportData reportData = createTestReportDataWithAlerts(template);
        Context context = createTestContext(reportData);
        StringWriter writer = new StringWriter();

        /* execute */
        templateEngine.process(template.getReportTemplateFile().getAbsolutePath(), context, writer);

        /* test */
        String sarifReportJSON = writer.getBuffer().toString();
        assertNotNull(sarifReportJSON);

        InspectionContext inspectionContext = new InspectionContext();

        JsonNode rootNode = assertValidJSON(sarifReportJSON);
        JsonNode firstRun = assertOneRunOnly(rootNode);
        assertResults(firstRun);
        assertTaxonomies(firstRun, inspectionContext);
        assertTool(firstRun, inspectionContext);
    }

    private void assertTool(JsonNode firstRun, InspectionContext inspectionContext) {
        SarifToolDataProvider owaspZap = SarifToolData.INSTANCE.getOwaspZap();
        SarifToolDataProvider cwe = SarifToolData.INSTANCE.getCwe();

        JsonNode tool = firstRun.get("tool");

        // driver
        JsonNode driver = tool.get("driver");
        assertEquals(owaspZap.getGuid(), driver.get("guid").asText());
        assertEquals(owaspZap.getInformationUri(), driver.get("informationUri").asText());
        assertEquals(owaspZap.getName(), driver.get("name").asText());
        assertEquals("99.9.9", driver.get("version").asText());
        assertEquals("99.9.9", driver.get("semanticVersion").asText());

        // driver - rules
        assertRules(inspectionContext, cwe, driver);

        // driver - supported taxonomies
        assertTaxonomies(cwe, driver);
    }

    private void assertTaxonomies(SarifToolDataProvider cwe, JsonNode driver) {
        JsonNode supportedTaxonomies = driver.get("supportedTaxonomies");
        assertTrue(supportedTaxonomies.isArray());
        ArrayNode supportedTaxonimiesArray = (ArrayNode) supportedTaxonomies;
        assertEquals(1, supportedTaxonimiesArray.size());
        JsonNode supportedTaxonmy = supportedTaxonimiesArray.iterator().next();
        assertEquals(cwe.getGuid(), supportedTaxonmy.get("guid").asText());
        assertEquals(cwe.getName(), supportedTaxonmy.get("name").asText());
    }

    private void assertRules(
            InspectionContext inspectionContext, SarifToolDataProvider cwe, JsonNode driver) {
        JsonNode rules = driver.get("rules");
        assertTrue(rules.isArray());
        ArrayNode rulesArray = (ArrayNode) rules;
        for (JsonNode rule : rulesArray) {
            assertRuleHasCweEntrAndGuidsNotDuplicated(inspectionContext, cwe, rule);
        }
        assertEquals(2, rulesArray.size());
        Iterator<JsonNode> ruleIt = rulesArray.iterator();
        assertRule1(ruleIt.next());
        assertRule2(ruleIt.next());
    }

    private void assertRule1(JsonNode rule) {
        // properties
        JsonNode properties = rule.get("properties");
        assertEquals("medium", properties.get("confidence").asText());
        assertEquals("Test Solution", properties.get("solution").get("text").asText());

        assertPropertiesContainReferences(properties, Collections.emptyList());
    }

    private void assertRule2(JsonNode rule) {
        // properties
        JsonNode properties = rule.get("properties");
        assertEquals("medium", properties.get("confidence").asText());
        assertEquals("Phase: 1\n\nDo ....", properties.get("solution").get("text").asText());

        List<String> expectedReferences = new ArrayList<>();
        expectedReferences.add("http://projects.webappsec.org/Cross-Site-Scripting");
        expectedReferences.add("http://cwe.mitre.org/data/definitions/79.html");

        assertPropertiesContainReferences(properties, expectedReferences);
    }

    private void assertPropertiesContainReferences(
            JsonNode properties, List<String> expectedReferences) {
        JsonNode references = properties.get("references");
        assertTrue(references.isArray());
        ArrayNode referencesArray = (ArrayNode) references;
        List<String> list = new ArrayList<>();
        for (JsonNode reference : referencesArray) {
            String referenceText = reference.asText();
            list.add(referenceText);
        }
        assertEquals(expectedReferences, list);
    }

    private void assertRuleHasCweEntrAndGuidsNotDuplicated(
            InspectionContext inspectionContext, SarifToolDataProvider cwe, JsonNode rule) {

        // relationships
        JsonNode relationShips = rule.get("relationships");
        assertTrue(relationShips.isArray());
        ArrayNode relationShipsArray = (ArrayNode) relationShips;
        for (JsonNode relationShip : relationShipsArray) {
            JsonNode target = relationShip.get("target");
            String targetId = target.get("id").asText();
            String targetGuid = target.get("guid").asText();

            JsonNode toolComponent = target.get("toolComponent");
            String toolComponentName = toolComponent.get("name").asText();
            String toolComponentGuid = toolComponent.get("guid").asText();

            switch (toolComponentName) {
                case "CWE":
                    assertEquals(
                            cwe.getGuid(),
                            toolComponentGuid,
                            "CWE guid not found as tool component guid!");
                    assertCWEGuidNotDifferent(
                            Integer.parseInt(targetId), targetGuid, inspectionContext);
                    break;
                default:
                    fail(
                            "This component name is not wellknown in test:"
                                    + toolComponentName
                                    + " - maybe new, but not tested tool component?");
            }
        }
    }

    private void configureTemplateEngine(String templateName) throws Exception {
        /* configure template engine */
        templateEngine = new TemplateEngine();
        template = ExtensionReportsUnitTest.getTemplateFromYamlFile(templateName);

        FileTemplateResolver templateResolver = new FileTemplateResolver();
        templateResolver.setTemplateMode(template.getMode());
        templateEngine.setTemplateResolver(templateResolver);
        templateEngine.setMessageResolver(new ReportMessageResolver(template));
    }

    private JsonNode assertValidJSON(String sarifReportJSON)
            throws JsonProcessingException, JsonMappingException {
        /* when debugging enabled dump JSON to system out: */
        if (Boolean.getBoolean("zap.extensions.reports.sarif.test.debug")) {
            System.out.println(sarifReportJSON);
        }

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readTree(sarifReportJSON);
    }

    private void assertTaxonomies(JsonNode firstRun, InspectionContext inspectionContext) {
        JsonNode taxonomies = firstRun.get("taxonomies");
        assertTrue(taxonomies.isArray());
        ArrayNode taxonomiesArray = (ArrayNode) taxonomies;

        // taxonomy: CWE
        assertEquals(1, taxonomiesArray.size()); // currently we provide only one: CWE
        JsonNode firstTaxonomy = taxonomiesArray.iterator().next();
        SarifToolDataProvider cwe = SarifToolData.INSTANCE.getCwe();
        assertEquals(cwe.getDownloadUri(), firstTaxonomy.get("downloadUri").asText());
        assertEquals(cwe.getInformationUri(), firstTaxonomy.get("informationUri").asText());

        // taxa
        JsonNode taxa = firstTaxonomy.get("taxa");
        assertTrue(taxa.isArray());
        ArrayNode taxaArray = (ArrayNode) taxa;
        assertEquals(2, taxaArray.size());
        Iterator<JsonNode> taxaIterator = taxaArray.iterator();
        JsonNode firstTaxa = taxaIterator.next();
        JsonNode secondTaxa = taxaIterator.next();

        assertEquals("79", firstTaxa.get("id").asText());
        assertEquals(
                "https://cwe.mitre.org/data/definitions/79.html",
                firstTaxa.get("helpUri").asText());
        String cwe79guid = firstTaxa.get("guid").asText();
        assertCWEGuidNotDifferent(79, cwe79guid, inspectionContext);

        assertEquals("693", secondTaxa.get("id").asText());
        assertEquals(
                "https://cwe.mitre.org/data/definitions/693.html",
                secondTaxa.get("helpUri").asText());
    }

    private void assertCWEGuidNotDifferent(
            int cweId, String expectedGuid, InspectionContext inspectionContext) {
        String guidFound = inspectionContext.cweIdToGuidMap.get(cweId);
        if (guidFound == null) {
            // just first registration
            inspectionContext.cweIdToGuidMap.put(cweId, expectedGuid);
        } else {
            // already registered - so test if registered with same guid
            assertEquals(
                    expectedGuid, guidFound, "Generated GUIDs are not same for CWE id:" + cweId);
        }
    }

    private void assertResults(JsonNode firstRun) {
        JsonNode results = firstRun.get("results");
        assertTrue(results.isArray());
        ArrayNode resultsArray = (ArrayNode) results;
        assertEquals(
                3,
                resultsArray
                        .size()); // 2 different rules, but css was found 2 times so 3 results at
        // all
        Iterator<JsonNode> resultiterator = resultsArray.iterator();

        assertCSS1Result(resultiterator);
        assertCSS2Result(resultiterator);
        assertCSPResult(resultiterator);
    }

    private void assertCSS1Result(Iterator<JsonNode> resultiterator) {
        JsonNode result = assertCSS1ResultFoundAndLocationAsExpected(resultiterator);

        // first result has "otherInfo" set, so we expect the other info expect the full description
        JsonNode message = result.get("message");
        JsonNode messageText = message.get("text");
        assertEquals(
                "Some other additional information which shall appear inside the message",
                messageText.asText());

        assertWebRequestOfCSS1Result(result);
        assertWebResponseOfCSS1Result(result);
    }

    private void assertCSS2Result(Iterator<JsonNode> resultiterator) {
        JsonNode result = assertCSS2ResultFoundAndLocationAsExpected(resultiterator);

        // first result has "otherInfo" set, so we expect the other info expect the full description
        JsonNode message = result.get("message");
        JsonNode messageText = message.get("text");
        assertEquals(
                "Some other additional information2 which shall appear inside the message",
                messageText.asText());
    }

    private JsonNode assertCSPResult(Iterator<JsonNode> resultiterator) {
        JsonNode secondResult = resultiterator.next();

        // second result has no "otherInfo" set, so we expect the description as fallback
        JsonNode message = secondResult.get("message");
        JsonNode messageText = message.get("text");
        assertEquals("CSP Description", messageText.asText());

        assertEquals("warning", secondResult.get("level").asText());
        assertEquals("1", secondResult.get("ruleId").asText());

        assertWebResponseOfSecondResult(secondResult);
        return secondResult;
    }

    private JsonNode assertCSS1ResultFoundAndLocationAsExpected(Iterator<JsonNode> resultiterator) {
        /* first */
        JsonNode firstResult = resultiterator.next();

        assertEquals("error", firstResult.get("level").asText());
        assertEquals("40012", firstResult.get("ruleId").asText());

        JsonNode locations = firstResult.get("locations");
        assertTrue(locations.isArray());
        ArrayNode locationsArray = (ArrayNode) locations;
        assertEquals(1, locationsArray.size());
        JsonNode firstLocation = locationsArray.iterator().next();

        // first location - physical parts
        JsonNode physicalLocation = firstLocation.get("physicalLocation");
        JsonNode artifactLocation = physicalLocation.get("artifactLocation");
        JsonNode artifactLocationUri = artifactLocation.get("uri");
        assertEquals(FINDING_1_URI, artifactLocationUri.asText());

        JsonNode region = physicalLocation.get("region");
        JsonNode startLine = region.get("startLine");
        JsonNode snippet = region.get("snippet");
        JsonNode snippetText = snippet.get("text");

        String snipppetTextString = snippetText.asText();
        long startLineLong = startLine.asLong();
        assertEquals(10, startLineLong);
        assertEquals("</p><script>alert(1);</script><p>", snipppetTextString);

        // first location - properties
        JsonNode properties = firstLocation.get("properties");
        JsonNode attack = properties.get("attack");
        JsonNode evidence = properties.get("evidence");

        assertEquals("</p><script>alert(1);</script><p>", attack.asText());
        assertEquals("</p><script>alert(1);</script><p>", evidence.asText());

        return firstResult;
    }

    private JsonNode assertCSS2ResultFoundAndLocationAsExpected(Iterator<JsonNode> resultiterator) {
        /* first */
        JsonNode firstResult = resultiterator.next();

        assertEquals("error", firstResult.get("level").asText());
        assertEquals("40012", firstResult.get("ruleId").asText());

        JsonNode locations = firstResult.get("locations");
        assertTrue(locations.isArray());
        ArrayNode locationsArray = (ArrayNode) locations;
        assertEquals(1, locationsArray.size());
        JsonNode firstLocation = locationsArray.iterator().next();

        // first location - physical parts
        JsonNode physicalLocation = firstLocation.get("physicalLocation");
        JsonNode artifactLocation = physicalLocation.get("artifactLocation");
        JsonNode artifactLocationUri = artifactLocation.get("uri");
        assertEquals(FINDING_2_URI, artifactLocationUri.asText());

        JsonNode region = physicalLocation.get("region");
        JsonNode startLine = region.get("startLine");
        JsonNode snippet = region.get("snippet");
        JsonNode snippetText = snippet.get("text");

        String snipppetTextString = snippetText.asText();
        long startLineLong = startLine.asLong();
        assertEquals(11, startLineLong);
        assertEquals("</p><script>alert(1);</script><p>", snipppetTextString);

        // first location - properties
        JsonNode properties = firstLocation.get("properties");
        JsonNode attack = properties.get("attack");
        JsonNode evidence = properties.get("evidence");

        assertEquals("</p><script>alert(1);</script><p>", attack.asText());
        assertEquals("</p><script>alert(1);</script><p>", evidence.asText());

        return firstResult;
    }

    private void assertWebResponseOfCSS1Result(JsonNode firstResult) {
        JsonNode webResponse = firstResult.get("webResponse");
        assertEquals("HTTP", webResponse.get("protocol").asText());
        assertEquals("1.1", webResponse.get("version").asText());
        assertEquals("200", webResponse.get("statusCode").asText());

        JsonNode body = webResponse.get("body");
        JsonNode bodyText = body.get("text");
        String bodyTextString = bodyText.asText();
        if (!bodyTextString.contains(">Getting Started:")) {
            fail("The body did contain expected content, but:\n" + bodyTextString);
        }
        JsonNode bodyBinary = body.get("binary");
        assertNull(bodyBinary, "binary does exist in body JSON but may not!");
    }

    private void assertWebResponseOfSecondResult(JsonNode secondResult) {
        JsonNode webResponse = secondResult.get("webResponse");
        assertEquals("HTTP", webResponse.get("protocol").asText());
        assertEquals("1.0", webResponse.get("version").asText());
        assertEquals("200", webResponse.get("statusCode").asText());

        JsonNode body = webResponse.get("body");
        JsonNode bodyBinary = body.get("binary");
        String bodyBInaryBase64String = bodyBinary.asText();
        if (!bodyBInaryBase64String.contains("VGVzdCBSZXNwb25zZSBCb2R5")) {
            fail("The body did contain expected content, but:\n" + bodyBInaryBase64String);
        }
        JsonNode bodyText = body.get("text");
        assertNull(bodyText, "text does exist in body json but may not!");
    }

    private void assertWebRequestOfCSS1Result(JsonNode firstResult) {
        JsonNode webRequest = firstResult.get("webRequest");
        assertEquals(FINDING_1_URI, webRequest.get("target").asText());
        assertEquals("HTTP", webRequest.get("protocol").asText());
        assertEquals("1.1", webRequest.get("version").asText());
        assertEquals("GET", webRequest.get("method").asText());

        JsonNode body = webRequest.get("body");
        JsonNode text = body.get("text");
        JsonNode binary = body.get("binary");
        assertEquals(null, text); // we did not sent text body
        assertEquals(null, binary); // we did not sent binary body
    }

    private JsonNode assertOneRunOnly(JsonNode rootNode) {
        JsonNode runs = rootNode.get("runs");
        assertTrue(runs.isArray());
        ArrayNode runsArray = (ArrayNode) runs;
        assertEquals(1, runsArray.size());
        JsonNode firstRun = runsArray.get(0);
        return firstRun;
    }

    private Context createTestContext(ReportData reportData) {
        Context context = new Context();
        context.setVariable("alertTree", reportData.getAlertTreeRootNode());
        context.setVariable("reportTitle", reportData.getTitle());
        context.setVariable("description", reportData.getDescription());
        context.setVariable("helper", new ReportHelper());
        context.setVariable("zapVersion", "99.9.9");
        context.setVariable("reportData", reportData);
        context.setVariable("report", reportData);
        return context;
    }

    private static ReportData createTestReportDataWithAlerts(Template template)
            throws URIException, HttpMalformedHeaderException {
        ReportData reportData = new ReportData();
        reportData.setTitle("Test Title");
        reportData.setDescription("Test Description");
        reportData.setIncludeAllConfidences(true);
        reportData.setSections(template.getSections());
        reportData.setIncludeAllRisks(true);

        List<PluginPassiveScanner> list = new ArrayList<>();
        PassiveScanJobResultData pscanData = new PassiveScanJobResultData("passiveScan-wait", list);
        reportData.addReportObjects(pscanData.getKey(), pscanData);

        AlertNode rootAlertNode =
                new AlertNode(0, "TestRootNode"); // represents root node at top of alert tree in UI
        reportData.setAlertTreeRootNode(rootAlertNode);
        /** @formatter:off */
        Alert cssAlert =
                newAlertBuilder()
                        .setName("Cross Site Scripting")
                        .setPluginId(40012)
                        .setDescription("CSS Description\nMultiple lines\n\nEnd")
                        .setUriString(FINDING_1_URI)
                        .setAttack("</p><script>alert(1);</script><p>")
                        .setEvidence("</p><script>alert(1);</script><p>")
                        .setRequestHeader(
                                "GET "
                                        + FINDING_1_URI
                                        + " HTTP/1.1\n"
                                        + "Host: 127.0.0.1:8080\n"
                                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\n"
                                        + "Pragma: no-cache\n"
                                        + "Cache-Control: no-cache\n"
                                        + "Referer: https://127.0.0.1:8080/hello\n"
                                        + "Cookie: JSESSIONID=38AA1F7A61982DF1073D7F43A3707798; locale=de\n"
                                        + "Content-Length: 0\n")
                        .setResponseHeader(
                                "HTTP/1.1 200\n"
                                        + "Set-Cookie: locale=de; HttpOnly; SameSite=strict\n"
                                        + "X-Content-Type-Options: nosniff\n"
                                        + "X-XSS-Protection: 1; mode=block\n"
                                        + "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\n"
                                        + "Pragma: no-cache\n"
                                        + "Expires: 0\n"
                                        + "Strict-Transport-Security: max-age=31536000 ; includeSubDomains\n"
                                        + "X-Frame-Options: DENY\n"
                                        + "Content-Security-Policy: script-src 'self'\n"
                                        + "Referrer-Policy: no-referrer\n"
                                        + "Content-Type: text/html;charset=UTF-8\n"
                                        + "Content-Language: en-US\n"
                                        + "Date: Thu, 11 Nov 2021 09:56:20 GMT\n"
                                        + "")
                        .setResponseBody(
                                "<!DOCTYPE HTML>\n"
                                        + "<html>\n"
                                        + "<head>\n"
                                        + "    <title>Getting Started: Serving Web Content</title>\n"
                                        + "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
                                        + "</head>\n"
                                        + "<body>\n"
                                        + "    <!-- unsecure text used (th:utext instead th:text)- to create vulnerability (XSS) -->\n"
                                        + "    <!-- simple usage: http://localhost:8080/greeting?name=Test2</p><script>;alert(\"hallo\")</script> -->\n"
                                        + "    <p >XSS attackable parameter output: </p><script>alert(1);</script><p>!</p>\n"
                                        + "</body>\n"
                                        + "</html>")
                        .setReference(
                                "<p>http://projects.webappsec.org/Cross-Site-Scripting</p><p>http://cwe.mitre.org/data/definitions/79.html</p>")
                        .setSolution("<p>Phase: 1</p>\nDo ....")
                        .setCweId(79)
                        .setWascId(8)
                        .setOtherInfo(
                                "Some other <b>additional</b> information which shall appear inside the message")
                        .setRisk(Alert.RISK_HIGH)
                        .build();

        rootAlertNode.add(
                newAlertNodeBuilder(cssAlert)
                        .newInstance()
                        .setUri(FINDING_2_URI)
                        .setRequestHeader(
                                "GET "
                                        + FINDING_2_URI
                                        + " HTTP/1.1\n"
                                        + "Host: 127.0.0.1:8080\n"
                                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0\n"
                                        + "Pragma: no-cache\n"
                                        + "Cache-Control: no-cache\n"
                                        + "Referer: https://127.0.0.1:8080/hello\n"
                                        + "Cookie: JSESSIONID=38AA1F7A61982DF1073D7F43A3707798; locale=de\n"
                                        + "Content-Length: 0\n")
                        .setResponseHeader(
                                "HTTP/1.1 200\n"
                                        + "Set-Cookie: locale=de; HttpOnly; SameSite=strict\n"
                                        + "X-Content-Type-Options: nosniff\n"
                                        + "X-XSS-Protection: 1; mode=block\n"
                                        + "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\n"
                                        + "Pragma: no-cache\n"
                                        + "Expires: 0\n"
                                        + "Strict-Transport-Security: max-age=31536000 ; includeSubDomains\n"
                                        + "X-Frame-Options: DENY\n"
                                        + "Content-Security-Policy: script-src 'self'\n"
                                        + "Referrer-Policy: no-referrer\n"
                                        + "Content-Type: text/html;charset=UTF-8\n"
                                        + "Content-Language: en-US\n"
                                        + "Date: Thu, 11 Nov 2021 09:56:20 GMT\n"
                                        + "")
                        .setResponseBody(
                                "<!DOCTYPE HTML>\n"
                                        + "<html>\n"
                                        + "<head>\n"
                                        + "    <title>Getting Started2: Serving Web Content</title>\n"
                                        + "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
                                        + "</head>\n"
                                        + "<body>\n"
                                        + "    <!-- Additional line to have other startline in Test -->\n"
                                        + "    <!-- unsecure text used (th:utext instead th:text)- to create vulnerability (XSS) -->\n"
                                        + "    <!-- simple usage: http://localhost:8080/greeting2?name=Test2</p><script>;alert(\"hallo\")</script> -->\n"
                                        + "    <p >XSS attackable parameter output: </p><script>alert(1);</script><p>!</p>\n"
                                        + "</body>\n"
                                        + "</html>")
                        .setOtherInfo(
                                "Some other additional information2 which shall appear inside the message")
                        .add()
                        .build());

        Alert cspAlert =
                newAlertBuilder()
                        .setName("CSP")
                        .setResponseHeader(
                                "HTTP/1.0 200\n"
                                        + "Set-Cookie: locale=de; HttpOnly; SameSite=strict\n"
                                        + "X-Content-Type-Options: nosniff\n"
                                        + "X-XSS-Protection: 1; mode=block\n"
                                        + "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\n"
                                        + "Pragma: no-cache\n"
                                        + "Expires: 0\n"
                                        + "Strict-Transport-Security: max-age=31536000 ; includeSubDomains\n"
                                        + "X-Frame-Options: DENY\n"
                                        + "Content-Security-Policy: script-src 'self'\n"
                                        + "Referrer-Policy: no-referrer\n"
                                        + "Content-Type: application/pdf\n"
                                        + "Content-Language: en-US\n"
                                        + "Date: Thu, 11 Nov 2021 09:56:20 GMT\n"
                                        + "")
                        .setCweId(693)
                        .setUriString("https://127.0.0.1:8080")
                        .setDescription("CSP Description")
                        .setRisk(Alert.RISK_MEDIUM)
                        .build();

        rootAlertNode.add(newAlertNodeBuilder(cspAlert).build());

        reportData.setSites(Arrays.asList("https://127.0.0.1"));
        /** @formatter:on */
        return reportData;
    }

    private class InspectionContext {

        private Map<Integer, String> cweIdToGuidMap = new TreeMap<Integer, String>();
    }
}
