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
package org.zaproxy.gradle.tasks;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.TaskAction;

public class GenerateGraphiQlHtmlPage extends DefaultTask {

    @TaskAction
    public void generate() throws IOException {
        String indexHtmlString =
                FileUtils.readFileToString(
                        getInputs()
                                .getFiles()
                                .filter(e -> "index.html".equals(e.getName()))
                                .getSingleFile(),
                        StandardCharsets.UTF_8);
        Set<File> resourceFiles =
                getInputs()
                        .getFiles()
                        .filter(e -> e.getName().matches(".*\\.(css|js)$"))
                        .getFiles();
        for (File resourceFile : resourceFiles) {
            String resourceString =
                    FileUtils.readFileToString(resourceFile, StandardCharsets.UTF_8);
            indexHtmlString =
                    indexHtmlString.replace("{{" + resourceFile.getName() + "}}", resourceString);
        }
        FileUtils.writeStringToFile(
                getOutputs().getFiles().getSingleFile(), indexHtmlString, StandardCharsets.UTF_8);
    }
}
