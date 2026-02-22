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
package org.zaproxy.addon.llm.context;

import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;

public class LlmZapLogTailBuilder {

    private static final int DEFAULT_MAX_LINES = 500;
    private static final int MAX_BYTES_READ = 512 * 1024; // 512 KiB
    private static final int DEFAULT_MAX_FILES = 3;
    private static final Pattern ROTATED_LOG_PATTERN = Pattern.compile("^zap\\.log(?:\\.(\\d+))?$");

    private final int maxLines;
    private final int maxFiles;

    public LlmZapLogTailBuilder() {
        this(DEFAULT_MAX_LINES, DEFAULT_MAX_FILES);
    }

    public LlmZapLogTailBuilder(int maxLines) {
        this(maxLines, DEFAULT_MAX_FILES);
    }

    public LlmZapLogTailBuilder(int maxLines, int maxFiles) {
        this.maxLines = Math.max(50, maxLines);
        this.maxFiles = Math.max(1, maxFiles);
    }

    public Map<String, Object> buildZapLogTail() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "zap_logs_tail");
        payload.put("max_lines", maxLines);
        payload.put("max_files", maxFiles);

        Path zapHome = Paths.get(Constant.getZapHome());
        if (!Files.isDirectory(zapHome)) {
            payload.put("available", false);
            return payload;
        }

        payload.put("available", true);
        payload.put("files", buildLogFiles(zapHome));
        return payload;
    }

    private List<Map<String, Object>> buildLogFiles(Path zapHome) {
        List<Path> logPaths = listLogFiles(zapHome);
        List<Map<String, Object>> files = new ArrayList<>(logPaths.size());

        for (Path logPath : logPaths) {
            Map<String, Object> filePayload = new LinkedHashMap<>();
            filePayload.put("path", logPath.toString());
            filePayload.put("available", Files.isRegularFile(logPath));
            filePayload.put("lines", tailLines(logPath, maxLines));
            files.add(filePayload);
        }

        return files;
    }

    private List<Path> listLogFiles(Path zapHome) {
        List<Path> result = new ArrayList<>();

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(zapHome, "zap.log*")) {
            for (Path p : stream) {
                if (!Files.isRegularFile(p)) {
                    continue;
                }
                String fileName = p.getFileName().toString();
                if ("zap.log.lck".equalsIgnoreCase(fileName)) {
                    continue;
                }
                Matcher matcher = ROTATED_LOG_PATTERN.matcher(fileName);
                if (!matcher.matches()) {
                    continue;
                }
                result.add(p);
            }
        } catch (Exception e) {
            // ignored, handled by returning an empty list.
        }

        // Sort by rotation number (zap.log is considered 0), then take newest (lowest number)
        // first.
        result.sort(
                (a, b) -> {
                    int ra = rotationNumber(a.getFileName().toString());
                    int rb = rotationNumber(b.getFileName().toString());
                    return Integer.compare(ra, rb);
                });

        if (result.size() > maxFiles) {
            return result.subList(0, maxFiles);
        }
        return result;
    }

    private static int rotationNumber(String fileName) {
        Matcher matcher = ROTATED_LOG_PATTERN.matcher(fileName);
        if (!matcher.matches()) {
            return Integer.MAX_VALUE;
        }
        String group = matcher.group(1);
        if (group == null) {
            return 0;
        }
        try {
            return Integer.parseInt(group);
        } catch (NumberFormatException e) {
            return Integer.MAX_VALUE;
        }
    }

    private static List<String> tailLines(Path path, int maxLines) {
        Charset charset = Charset.defaultCharset();
        if (!Files.isRegularFile(path)) {
            return List.of("Log file not found: " + path);
        }
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "r")) {
            long len = raf.length();
            long pos = len;
            int bytesRead = 0;
            int lineCount = 0;
            List<Byte> bytes = new ArrayList<>();

            while (pos > 0 && lineCount <= maxLines && bytesRead < MAX_BYTES_READ) {
                pos--;
                raf.seek(pos);
                int b = raf.read();
                bytesRead++;

                if (b == '\n') {
                    lineCount++;
                    if (lineCount > maxLines) {
                        break;
                    }
                }
                bytes.add((byte) b);
            }

            // Reverse bytes into a byte[]
            byte[] data = new byte[bytes.size()];
            for (int i = 0; i < bytes.size(); i++) {
                data[i] = bytes.get(bytes.size() - 1 - i);
            }

            String text = new String(data, charset);
            // Normalise and split.
            String[] lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n", -1);
            List<String> result = new ArrayList<>(lines.length);
            for (String line : lines) {
                // Avoid returning a trailing empty line that comes from split(-1).
                if (result.isEmpty() && line.isEmpty()) {
                    continue;
                }
                result.add(line);
            }
            return result;
        } catch (Exception e) {
            return List.of("Failed to read zap.log: " + e.getMessage());
        }
    }
}
