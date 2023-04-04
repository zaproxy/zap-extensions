/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.RequestBody;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.openapi.AbstractOpenApiTest;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.network.RequestMethod;

/** Unit test for {@link RequestModelConverter}. */
class RequestModelConverterUnitTest extends AbstractOpenApiTest {

    @Test
    void shouldConvertRequestBodyWithNullContent() {
        // Given
        Operation operation = new Operation();
        operation.setRequestBody(new RequestBody());
        OperationModel operationModel =
                new OperationModel("/api/test", operation, RequestMethod.POST);

        RequestModelConverter converter = new RequestModelConverter();
        // When / Then
        assertDoesNotThrow(() -> converter.convert(operationModel, new Generators(null)));
    }
}
