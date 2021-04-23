/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.support.HierarchyTraversalMode;
import org.junit.platform.commons.support.ReflectionSupport;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.NanoServerHandler;

public class ExtensionOpenApiTest extends AbstractServerTest {

    private ExtensionOpenApi classUnderTest;

    @BeforeEach
    public void setup() throws Exception {
        classUnderTest = new ExtensionOpenApi();

        Control control = mock(Control.class, withSettings().lenient());
        setControlSingleton(control);

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        when(control.getExtensionLoader()).thenReturn(extensionLoader);

        given(extensionLoader.getExtension(ExtensionSpider.class))
                .willReturn(mock(ExtensionSpider.class));
    }

    @Test
    public void shouldFailWithInvalidOverrideUrl() throws IOException {
        // given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json"));
        String fileContents =
                getHtml(
                        "PetStore_defn.json",
                        new String[][] {{"PORT", String.valueOf(this.nano.getListeningPort())}});
        File tmpFile = File.createTempFile("foo", "bar");
        FileUtils.write(tmpFile, fileContents, Charset.defaultCharset());

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(tmpFile, "htp:/", false);

        // then
        assertThat("Should fail because of bad target override URL", !errors.isEmpty());
    }

    @Test
    public void shouldImportFile() throws IOException {
        // given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json"));
        String fileContents =
                getHtml(
                        "PetStore_defn.json",
                        new String[][] {{"PORT", String.valueOf(this.nano.getListeningPort())}});
        File tmpFile = File.createTempFile("foo", "bar");
        FileUtils.write(tmpFile, fileContents, Charset.defaultCharset());

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(tmpFile, false);

        // then
        assertThat("Should parse OK: " + errors, errors.isEmpty());
    }

    @Test
    public void shouldImportMultiFileV3() {
        // given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String file = "v3/multi-file/api.yaml";
        this.nano.addHandler(new DefnServerHandler(test, defnName, file));

        // when
        List<String> errors =
                classUnderTest.importOpenApiDefinition(getResourcePath(file).toFile(), false);

        // then
        assertThat("Should parse OK: " + errors, errors.isEmpty());
    }

    @Test
    public void shouldImportMultiFileV2() {
        // given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String file = "v2/multi-file/api.yaml";
        this.nano.addHandler(new DefnServerHandler(test, defnName, file));

        // when
        List<String> errors =
                classUnderTest.importOpenApiDefinition(getResourcePath(file).toFile(), false);

        // then
        assertThat("Should parse OK: " + errors, errors.isEmpty());
    }

    @Test
    public void shouldFailNonOpenApiURL() throws URIException {

        // given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json"));
        URI uri = new URI("http://localhost:" + this.nano.getListeningPort() + "/fake", false);

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(uri, null, false);

        // then
        assertThat("Should fail fake URL", errors != null && !errors.isEmpty());
    }

    @Test
    public void shouldFailNonExistentUrl() throws URIException {

        // given
        URI uri = new URI("http://foo", false);

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(uri, null, false);

        // then
        assertThat("Should fail fake URL", errors != null && !errors.isEmpty());
    }

    @Test
    public void shouldFailBadJson() {
        // given
        File file = getResourcePath("bad-json.json").toFile();

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(file, false);

        // then
        assertThat("Should fail to parse bad json", !errors.isEmpty());
    }

    @Test
    public void shouldFailBadYaml() {
        // given
        File file = getResourcePath("bad-yaml.yml").toFile();

        // when
        List<String> errors = classUnderTest.importOpenApiDefinition(file, false);

        // then
        assertThat("Should fail to parse bad yaml", !errors.isEmpty());
    }

    @Test
    public void shouldGenerateDataDrivenNodesOnContextNoUrl() {
        // given
        File file = getResourcePath("v3/VAmPI_defn.json").toFile();
        Context ctx = getDefaultContext();

        // when
        classUnderTest.importOpenApiDefinition(file, false, ctx.getId());

        // then
        assertThat(
                "Should have 2 data driven nodes in the context",
                ctx.getDataDrivenNodes().size() == 2);
    }

    @Test
    public void shouldGenerateDataDrivenNodesOnContext() {
        // given
        File file = getResourcePath("v3/VAmPI_defn.json").toFile();
        Context ctx = getDefaultContext();
        String targetUrl = "http://localhost:9000";

        // when
        classUnderTest.importOpenApiDefinition(file, targetUrl, false, ctx.getId());

        // then
        assertThat(
                "Should have 2 data driven nodes in the context",
                ctx.getDataDrivenNodes().size() == 2);
        assertThat(
                "Should start with targetUrl",
                ctx.getDataDrivenNodes().get(0).getPattern().pattern().startsWith(targetUrl));
    }

    @Test
    public void shouldGenerateDataDrivenNodesOnContextForMultiVarPath() {
        // given
        File file = getResourcePath("v3/MultiVarPath_defn.yaml").toFile();
        Context ctx = getDefaultContext();
        String targetUrl = "http://localhost:9000";

        // when
        classUnderTest.importOpenApiDefinition(file, targetUrl, false, ctx.getId());

        // then
        assertThat(
                "Should have 2 data driven nodes in the context",
                ctx.getDataDrivenNodes().size() == 2);
        assertThat(
                "Should start with targetUrl",
                ctx.getDataDrivenNodes().get(0).getPattern().pattern().startsWith(targetUrl));
    }

    private Context getDefaultContext() {
        String ctxName = "Default Content";
        Context ctx = Model.getSingleton().getSession().getContext(ctxName);
        if (ctx == null) {
            ctx = Model.getSingleton().getSession().getNewContext(ctxName);
        }
        return ctx;
    }

    private static void setControlSingleton(Control control) throws Exception {
        Field field =
                ReflectionSupport.findFields(
                                Control.class,
                                f -> "control".equals(f.getName()),
                                HierarchyTraversalMode.TOP_DOWN)
                        .get(0);
        field.setAccessible(true);
        field.set(Control.class, control);
    }

    private class DefnServerHandler extends NanoServerHandler {

        private final String defnName;
        private final String defnFileName;
        private final String port;

        public DefnServerHandler(String name, String defnName, String defnFileName) {
            this(name, defnName, defnFileName, nano.getListeningPort());
        }

        public DefnServerHandler(String name, String defnName, String defnFileName, int port) {
            super(name);
            this.defnName = defnName;
            this.defnFileName = defnFileName;
            this.port = String.valueOf(port);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            String response;
            if (session.getUri().endsWith(defnName)) {
                response = getHtml(defnFileName, new String[][] {{"PORT", port}});
            } else {
                // We dont actually care about the response in this handler ;)
                response = getHtml("Blank.html");
            }
            return newFixedLengthResponse(response);
        }
    }
}
