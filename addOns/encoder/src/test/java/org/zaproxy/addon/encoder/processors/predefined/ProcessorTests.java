/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.predefined;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.encoder.EncodeDecodeOptions;
import org.zaproxy.addon.encoder.ExtensionEncoder;
import org.zaproxy.addon.encoder.processors.EncodeDecodeProcessor;
import org.zaproxy.addon.encoder.processors.EncodeDecodeResult;

public abstract class ProcessorTests<T extends EncodeDecodeProcessor> {

    protected T processor;

    EncodeDecodeOptions options;

    @BeforeEach
    public void setUp() throws Exception {
        processor = createProcessor();

        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionEncoder extEnc =
                mock(ExtensionEncoder.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionEncoder.class)).willReturn(extEnc);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        options = mock(EncodeDecodeOptions.class);
        given(extEnc.getOptions()).willReturn(options);
        given(options.getBase64Charset()).willReturn(EncodeDecodeOptions.DEFAULT_CHARSET);
    }

    protected abstract T createProcessor();

    @TestFactory
    Collection<DynamicTest> commonPredefinedProcessorTests() {
        List<DynamicTest> commonTests = new ArrayList<>();
        commonTests.add(testProcessorHandleEmptyInput());
        return commonTests;
    }

    private DynamicTest testProcessorHandleEmptyInput() {
        return dynamicTest("shouldHandleEmptyInput", () -> shouldHandleEmptyInput());
    }

    void shouldHandleEmptyInput() throws Exception {
        // Given / When
        EncodeDecodeResult result = processor.process("");
        // Then
        assertThat(result.hasError(), is(equalTo(false)));
        assertThat(result.getResult(), is(equalTo("")));
    }
}
