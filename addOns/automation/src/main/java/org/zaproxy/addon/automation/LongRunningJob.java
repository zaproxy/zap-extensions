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
package org.zaproxy.addon.automation;

/**
 * Marker interface for automation jobs that run for an extended period.
 *
 * <p>Jobs implementing this interface provide a unique identifier and progress information.
 */
public interface LongRunningJob {

    /**
     * Returns a unique identifier for this job instance.
     *
     * @return the job id, or {@code null} if the job has not yet started and obtained an id
     */
    String getScanId();

    /**
     * Returns the progress of the job as a percentage (0-100).
     *
     * @return the progress percentage
     */
    int getScanProgress();
}
