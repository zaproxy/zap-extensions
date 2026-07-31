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
package org.zaproxy.addon.llmlocal;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.CommandLineListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmChatModelFactory;
import org.zaproxy.addon.llm.LlmLocalModelDownloadUi;

/**
 * Registers a Jlama-backed {@link LlmChatModelFactory} with the LLM add-on so local SafeTensors
 * models can be used in-process.
 */
public class ExtensionLlmLocal extends ExtensionAdaptor implements CommandLineListener {

    public static final String NAME = "ExtensionLlmLocal";

    protected static final String PREFIX = "llmlocal";

    private static final int REQUIRED_JAVA_FEATURE = 21;

    private static final int ARG_LLMLOCAL_IDX = 0;
    private static final int ARG_JLAMA_ALIAS_IDX = 1;

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionLlm.class);

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlmLocal.class);

    private LlmChatModelFactory factory;
    private LlmLocalModelDownloadUi downloadUi;
    private CommandLineArgument[] arguments = new CommandLineArgument[2];

    public ExtensionLlmLocal() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString(PREFIX + ".name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addCommandLine(getCommandLineArguments());

        if (!isSupportedJavaVersion()) {
            LOGGER.warn(
                    Constant.messages.getString(
                            "llmlocal.error.java.version", Runtime.version().feature()));
            return;
        }

        if (!JlamaRuntime.isVectorApiAvailable()) {
            LOGGER.warn(Constant.messages.getString("llmlocal.error.vector.api"));
        } else if (!JlamaRuntime.isNativeSimdAvailable()) {
            LOGGER.warn(Constant.messages.getString("llmlocal.error.native.simd"));
        }

        factory = new JlamaLlmChatModelFactory();
        getExtensionLlm().registerChatModelFactory(factory);
        downloadUi = new JlamaLocalModelDownloadUi();
        getExtensionLlm().registerLocalModelDownloadUi(downloadUi);
        LOGGER.info("Registered local LLM chat model factory (Jlama).");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        ExtensionLlm extensionLlm = getExtensionLlm();
        if (extensionLlm != null) {
            if (factory != null) {
                extensionLlm.unregisterChatModelFactory(factory);
            }
            if (downloadUi != null) {
                extensionLlm.unregisterLocalModelDownloadUi(downloadUi);
            }
        }
        factory = null;
        downloadUi = null;
        super.unload();
    }

    static boolean isSupportedJavaVersion() {
        return Runtime.version().feature() >= REQUIRED_JAVA_FEATURE;
    }

    private CommandLineArgument[] getCommandLineArguments() {
        arguments[ARG_LLMLOCAL_IDX] =
                new CommandLineArgument(
                        "-llmlocal",
                        1,
                        null,
                        "",
                        "-llmlocal <model>        "
                                + Constant.messages.getString("llmlocal.cmdline.help"));
        // Deprecated alias for the previous -jlama flag.
        arguments[ARG_JLAMA_ALIAS_IDX] =
                new CommandLineArgument(
                        "-jlama",
                        1,
                        null,
                        "",
                        "-jlama <model>           "
                                + Constant.messages.getString("llmlocal.cmdline.help.alias"));
        return arguments;
    }

    @Override
    public void execute(CommandLineArgument[] args) {
        String modelId = enabledModelId();
        if (modelId == null) {
            return;
        }

        if (!isSupportedJavaVersion()) {
            CommandLine.error(
                    Constant.messages.getString(
                            "llmlocal.error.java.version", Runtime.version().feature()));
            return;
        }

        if (factory == null) {
            CommandLine.error(Constant.messages.getString("llmlocal.error.factory.unavailable"));
            return;
        }

        try {
            CommandLine.info(
                    Constant.messages.getString("llmlocal.cmdline.download.start", modelId));
            Path modelDir = JlamaModelConfigurator.downloadAndConfigure(getExtensionLlm(), modelId);
            CommandLine.info(
                    Constant.messages.getString(
                            "llmlocal.cmdline.download.done", modelDir.toAbsolutePath()));
        } catch (IllegalArgumentException e) {
            CommandLine.error(e.getMessage());
        } catch (Exception e) {
            LOGGER.error("Failed to download/configure local LLM model {}", modelId, e);
            CommandLine.error(
                    Constant.messages.getString(
                            "llmlocal.cmdline.download.fail", modelId, e.getMessage()));
        }
    }

    private String enabledModelId() {
        if (arguments[ARG_LLMLOCAL_IDX].isEnabled()) {
            return arguments[ARG_LLMLOCAL_IDX].getArguments().get(0);
        }
        if (arguments[ARG_JLAMA_ALIAS_IDX].isEnabled()) {
            return arguments[ARG_JLAMA_ALIAS_IDX].getArguments().get(0);
        }
        return null;
    }

    @Override
    public boolean handleFile(File file) {
        return false;
    }

    @Override
    public List<String> getHandledExtensions() {
        return null;
    }

    private static ExtensionLlm getExtensionLlm() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionLlm.class);
    }
}
