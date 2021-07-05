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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.extension.params.HtmlParameterStats;
import org.zaproxy.zap.extension.params.SiteParameters;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ParamsJobResultDataUnitTest {

    private static final String EXAMPLE_SITE = "www.example.com";

    private static MockedStatic<CommandLine> mockedCmdLine;

    private ExtensionLoader extensionLoader;
    private ExtensionParams extParams;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);

        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extParams = mock(ExtensionParams.class);
        given(extensionLoader.getExtension(ExtensionParams.class)).willReturn(extParams);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnRightDataKeys() {
        // Given
        ParamsJobResultData data = new ParamsJobResultData("");

        // When
        String key = data.getKey();

        // Then
        assertThat(key, is(equalTo("paramsData")));
    }

    @Test
    void shouldGetSiteParameters() {
        // Given
        ParamsJobResultData data = new ParamsJobResultData("");
        SiteParameters siteParams = new SiteParameters(extParams, "");
        given(extParams.getSiteParameters(EXAMPLE_SITE)).willReturn(siteParams);

        // When
        SiteParameters params1 = data.getSiteParameters(EXAMPLE_SITE);
        SiteParameters params2 = data.getSiteParameters("https://" + EXAMPLE_SITE);
        SiteParameters params3 = data.getSiteParameters("https://www.example.org");

        // Then
        assertThat(params1, is(siteParams));
        assertThat(params2, is(siteParams));
        assertThat(params3, is(nullValue()));
    }

    @Test
    void shouldGetSortedSiteParams() {
        // Given
        ParamsJobResultData data = new ParamsJobResultData("");
        SiteParameters siteParams = mock(SiteParameters.class);
        given(extParams.getSiteParameters(EXAMPLE_SITE)).willReturn(siteParams);
        List<HtmlParameterStats> exampleParams = new ArrayList<>();
        given(siteParams.getParams()).willReturn(exampleParams);
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "u2", HtmlParameter.Type.url, null, null));
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "f2", HtmlParameter.Type.form, null, null));
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "c2", HtmlParameter.Type.cookie, null, null));
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "c1", HtmlParameter.Type.cookie, null, null));
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "u1", HtmlParameter.Type.url, null, null));
        exampleParams.add(
                new HtmlParameterStats(EXAMPLE_SITE, "f1", HtmlParameter.Type.form, null, null));

        // When
        List<HtmlParameterStats> params1 = data.getSortedSiteParams(EXAMPLE_SITE);
        List<HtmlParameterStats> params2 = data.getSortedSiteParams("https://www.example.org");

        // Then
        assertThat(params1.size(), is(equalTo(6)));
        assertThat(params1.get(0).getName(), is(equalTo("c1")));
        assertThat(params1.get(1).getName(), is(equalTo("c2")));
        assertThat(params1.get(2).getName(), is(equalTo("f1")));
        assertThat(params1.get(3).getName(), is(equalTo("f2")));
        assertThat(params1.get(4).getName(), is(equalTo("u1")));
        assertThat(params1.get(5).getName(), is(equalTo("u2")));
        assertThat(params2, is(nullValue()));
    }

    @Test
    void shouldGetAllSiteParameters() {
        // Given
        ParamsJobResultData data = new ParamsJobResultData("");
        Collection<SiteParameters> allSiteParams = new ArrayList<>();
        given(extParams.getAllSiteParameters()).willReturn(allSiteParams);

        // When
        Collection<SiteParameters> params = data.getAllSiteParameters();

        // Then
        assertThat(params, is(allSiteParams));
    }
}
