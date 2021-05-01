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
package org.zaproxy.zap.extension.soap.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.soap.ExtensionImportWSDL;
import org.zaproxy.zap.utils.I18N;

public class SoapJobUnitTest {

    private ExtensionImportWSDL extSoap;

    @BeforeEach
    public void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extSoap = mock(ExtensionImportWSDL.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionImportWSDL.class)).willReturn(extSoap);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    public void shouldReturnDefaultFields() {
        // Given / When
        SoapJob job = new SoapJob();

        // Then
        assertThat(job.getType(), is(equalTo("soap")));
        assertThat(job.getName(), is(equalTo("soap")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    public void shouldReturnCustomConfigParams() {
        // Given
        SoapJob job = new SoapJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(2)));
        assertThat(params.get("wsdlFile"), is(equalTo("")));
        assertThat(params.get("wsdlUrl"), is(equalTo("")));
    }

    @Test
    public void shouldApplyCustomConfigParams() {
        // Given
        SoapJob job = new SoapJob();
        String wsdlFile = "C:\\Users\\ZAPBot\\Documents\\test file.wsdl";
        String wsdlUrl = "https://example.com/test%20file.wsdl";

        // When
        job.applyCustomParameter("wsdlFile", wsdlFile);
        job.applyCustomParameter("wsdlUrl", wsdlUrl);

        // Then
        assertThat(job.getWsdlFile(), is(equalTo(wsdlFile)));
        assertThat(job.getWsdlUrl(), is(equalTo(wsdlUrl)));
    }

    @Test
    public void shouldFailIfInvalidUrl() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        SoapJob job = new SoapJob();
        // The following URL is invalid because it is not escaped.
        job.applyCustomParameter("wsdlUrl", "https://example.com/test file.wsdl");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!soap.automation.error.url!")));
    }

    @Test
    public void shouldFailIfInvalidFile() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        SoapJob job = new SoapJob();
        job.applyCustomParameter("wsdlFile", "Invalid file path.");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!soap.automation.error.file!")));
    }
}
