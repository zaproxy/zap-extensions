/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.MessageFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.prefs.Preferences;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import org.apache.log4j.Logger;
import org.owasp.jbrofuzz.core.Database;
import org.owasp.jbrofuzz.version.JBroFuzzPrefs;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.AddonFilesChangedListener;
import org.zaproxy.zap.extension.fuzz.payloads.generator.DefaultStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.JsonPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.NumberPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.RegexPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.ScriptStringPayloadGeneratorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.processor.Base64DecodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.Base64EncodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ExpandStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.JavaScriptEscapeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.JavaScriptUnescapeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.MD5HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PostfixStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PrefixStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA1HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA256HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.SHA512HashProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.processor.TrimStringProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.URLDecodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.URLEncodeProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUIHandlersRegistry;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultEmptyPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultEmptyPayloadGeneratorUIHandler.DefaultEmptyPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.DefaultStringPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.FileStringPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.JsonPayloadGeneratorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.NumberPayloadGeneratorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.RegexPayloadGeneratorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.impl.ScriptStringPayloadGeneratorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.Base64DecodeProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.Base64EncodeProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.ExpandStringProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.JavaScriptEscapeProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.JavaScriptUnescapeProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.MD5HashProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUIHandlersRegistry;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PostfixStringProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PrefixStringProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA1HashProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA256HashProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.SHA512HashProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.ScriptStringPayloadProcessorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.TrimStringProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.URLDecodeProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.URLEncodeProcessorUIHandler;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.view.ZapMenuItem;
import org.zaproxy.zap.view.messagecontainer.MessageContainer;
import org.zaproxy.zap.view.messagecontainer.SelectableContentMessageContainer;

public class ExtensionFuzz extends ExtensionAdaptor {

    private static final Logger LOGGER = Logger.getLogger(ExtensionFuzz.class);

    private static final ImageIcon SCRIPT_PAYLOAD_GENERATOR_ICON =
            new ImageIcon(
                    ExtensionFuzz.class.getResource(
                            "resources/icons/script-payload-generator.png"));
    private static final ImageIcon SCRIPT_PAYLOAD_PROCESSOR_ICON =
            new ImageIcon(
                    ExtensionFuzz.class.getResource(
                            "resources/icons/script-payload-processor.png"));

    public static final String NAME = "ExtensionFuzz";

    private static final String JBROFUZZ_CATEGORY_PREFIX = "jbrofuzz";

    private FuzzersController fuzzersController;

    private FuzzOptions fuzzOptions;

    private FuzzersStatusPanel fuzzScansPanel;
    private FuzzerUIStarterAction fuzzerStarter;
    private FuzzOptionsPanel fuzzOptionsPanel;

    private FuzzerPayloadCategory fuzzerPayloadJBroFuzzCategory;
    private FuzzersDir fuzzersDir;

    private List<FuzzersDirChangeListener> fuzzersDirChangeListeners;

    private List<FuzzerHandler<?, ?>> fuzzerHandlers;
    private FuzzerHandler<?, ?> defaultFuzzerHandler;
    private ScriptType scriptTypeGenerator;
    private ScriptType scriptTypeProcessor;
    private ZapMenuItem menuItemCustomScan = null;

    public ExtensionFuzz() {
        super(NAME);

        setI18nPrefix("fuzz");
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        super.init();

        // Force JBroFuzz to use the ZAP user directory
        Preferences PREFS = Preferences.userRoot().node("owasp/jbrofuzz");
        PREFS.putBoolean(JBroFuzzPrefs.DIRS[1].getId(), true);
        PREFS.put(JBroFuzzPrefs.DIRS[0].getId(), Constant.getZapHome());

        fuzzerHandlers = new ArrayList<>();
        fuzzersController = new FuzzersController();
        fuzzOptions = new FuzzOptions();

        fuzzerPayloadJBroFuzzCategory = loadJBroFuzzFuzzers();
        readFuzzersDir();
    }

    private FuzzerPayloadCategory createCustomFuzzerFilesCategory(List<FuzzerPayloadSource> files) {
        return new FuzzerPayloadCategory(
                getMessages().getString("fuzz.category.custom"),
                getMessages().getString("fuzz.category.custom"),
                Collections.<FuzzerPayloadCategory>emptyList(),
                files);
    }

    private static FuzzerPayloadCategory loadJBroFuzzFuzzers() {
        List<FuzzerPayloadCategory> fuzzerCategories = new ArrayList<>();
        Database jbroFuzzDB = new Database(Constant.getZapHome() + "jbrofuzz/fuzzers.jbrf");
        List<String> categories = new ArrayList<>(Arrays.asList(jbroFuzzDB.getAllCategories()));
        Collections.sort(categories);
        List<String> subCategoryNames = new ArrayList<>(2);
        subCategoryNames.add(JBROFUZZ_CATEGORY_PREFIX);
        for (String categoryName : categories) {
            subCategoryNames.add(categoryName);
            String[] fuzzers = jbroFuzzDB.getPrototypeNamesInCategory(categoryName);
            Arrays.sort(fuzzers);
            List<FuzzerPayloadSource> fuzzerSources = new ArrayList<>(fuzzers.length);
            for (String fuzzer : fuzzers) {
                fuzzerSources.add(
                        new FuzzerPayloadJBroFuzzSource(
                                fuzzer, jbroFuzzDB, jbroFuzzDB.getIdFromName(fuzzer)));
            }
            fuzzerCategories.add(
                    new FuzzerPayloadCategory(
                            categoryName,
                            createSubCategoryFullName(subCategoryNames),
                            Collections.<FuzzerPayloadCategory>emptyList(),
                            fuzzerSources));
            subCategoryNames.remove(subCategoryNames.size() - 1);
        }

        return new FuzzerPayloadCategory(
                JBROFUZZ_CATEGORY_PREFIX,
                JBROFUZZ_CATEGORY_PREFIX,
                fuzzerCategories,
                Collections.<FuzzerPayloadSource>emptyList());
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        fuzzerStarter = new FuzzerUIStarterAction();
        fuzzScansPanel = new FuzzersStatusPanel(fuzzOptions, fuzzersController, fuzzerStarter);
        fuzzOptionsPanel = new FuzzOptionsPanel(getMessages(), new CustomFileFuzzerAddedListener());
        fuzzOptionsPanel.setFuzzersDir(fuzzersDir);

        PayloadGeneratorUIHandlersRegistry payloadGeneratorsUIRegistry =
                PayloadGeneratorUIHandlersRegistry.getInstance();

        DefaultStringPayloadGeneratorUIHandler payloadGenerator =
                new DefaultStringPayloadGeneratorUIHandler();
        payloadGeneratorsUIRegistry.registerPayloadUI(
                DefaultStringPayloadGenerator.class, payloadGenerator);
        payloadGeneratorsUIRegistry.setDefaultPayloadGenerator(payloadGenerator);

        payloadGeneratorsUIRegistry.registerPayloadUI(
                FileStringPayloadGenerator.class, new FileStringPayloadGeneratorUIHandler());

        // TODO
        // payloadGeneratorsUIRegistry.registerPayloadUI(ProcessPayloadGenerator.class, new
        // ProcessPayloadGeneratorUIHandler());
        payloadGeneratorsUIRegistry.registerPayloadUI(
                RegexPayloadGenerator.class, new RegexPayloadGeneratorUIHandler());

        payloadGeneratorsUIRegistry.registerPayloadUI(
                DefaultEmptyPayloadGenerator.class, new DefaultEmptyPayloadGeneratorUIHandler());
        payloadGeneratorsUIRegistry.registerPayloadUI(
                NumberPayloadGenerator.class, new NumberPayloadGeneratorAdapterUIHandler());
        payloadGeneratorsUIRegistry.registerPayloadUI(
                JsonPayloadGenerator.class, new JsonPayloadGeneratorAdapterUIHandler());

        PayloadProcessorUIHandlersRegistry payloadProcessorsUIRegistry =
                PayloadProcessorUIHandlersRegistry.getInstance();
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                Base64DecodeProcessor.class, new Base64DecodeProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                Base64EncodeProcessor.class, new Base64EncodeProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                ExpandStringProcessor.class, new ExpandStringProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                JavaScriptEscapeProcessor.class, new JavaScriptEscapeProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                JavaScriptUnescapeProcessor.class, new JavaScriptUnescapeProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                MD5HashProcessor.class, new MD5HashProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                PostfixStringProcessor.class, new PostfixStringProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                PrefixStringProcessor.class, new PrefixStringProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                SHA1HashProcessor.class, new SHA1HashProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                SHA256HashProcessor.class, new SHA256HashProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                SHA512HashProcessor.class, new SHA512HashProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                TrimStringProcessor.class, new TrimStringProcessorUIHandler());
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                URLDecodeProcessor.class, new URLDecodeProcessorUIHandler());
        URLEncodeProcessorUIHandler urlEncodeProcessorUIHandler = new URLEncodeProcessorUIHandler();
        payloadProcessorsUIRegistry.registerProcessorUIHandler(
                URLEncodeProcessor.class, urlEncodeProcessorUIHandler);

        payloadProcessorsUIRegistry.setDefaultPayloadProcessor(urlEncodeProcessorUIHandler);

        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);

        if (extensionScript != null) {
            scriptTypeGenerator =
                    new ScriptType(
                            ScriptStringPayloadGenerator.TYPE_NAME,
                            "fuzz.payloads.script.type.payloadgenerator",
                            SCRIPT_PAYLOAD_GENERATOR_ICON,
                            true,
                            true);
            extensionScript.registerScriptType(scriptTypeGenerator);
            payloadGeneratorsUIRegistry.registerPayloadUI(
                    ScriptStringPayloadGeneratorAdapter.class,
                    new ScriptStringPayloadGeneratorAdapterUIHandler(extensionScript));

            scriptTypeProcessor =
                    new ScriptType(
                            ScriptStringPayloadProcessor.TYPE_NAME,
                            "fuzz.payloads.script.type.payloadprocessor",
                            SCRIPT_PAYLOAD_PROCESSOR_ICON,
                            true,
                            true);
            extensionScript.registerScriptType(scriptTypeProcessor);
            payloadProcessorsUIRegistry.registerProcessorUIHandler(
                    ScriptStringPayloadProcessorAdapter.class,
                    new ScriptStringPayloadProcessorAdapterUIHandler(extensionScript));
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(fuzzOptions);
        extensionHook.addAddonFilesChangedListener(new FuzzerFilesUpdater());

        if (getView() != null) {
            PayloadGeneratorUIHandlersRegistry payloadGeneratorsUIRegistry =
                    PayloadGeneratorUIHandlersRegistry.getInstance();
            payloadGeneratorsUIRegistry.registerPayloadUI(
                    FuzzerPayloadGenerator.class, new FuzzerPayloadGeneratorUIHandler(this));

            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemCustomScan());

            extensionHook.getHookView().addOptionPanel(fuzzOptionsPanel);

            extensionHook.getHookView().addStatusPanel(fuzzScansPanel);

            extensionHook.getHookMenu().addPopupMenuItem(new FuzzMessagePopupMenuItem(this));
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(new FuzzMessageWithLocationPopupMenuItem(this));

            extensionHook.addSessionListener(new FuzzerSessionListener());

            ExtensionHelp.enableHelpKey(fuzzScansPanel, "addon.fuzzer.tab");
        }
    }

    @Override
    public void unload() {
        super.unload();

        if (fuzzScansPanel != null) {
            fuzzScansPanel.unload();
        }

        if (getView() != null) {
            ExtensionScript extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);

            if (extensionScript != null) {
                extensionScript.removeScriptType(scriptTypeGenerator);
                extensionScript.removeScriptType(scriptTypeProcessor);
            }
        }
    }

    protected FuzzOptions getFuzzOptions() {
        return fuzzOptions;
    }

    @Override
    public String getUIName() {
        return getMessages().getString("fuzz.name");
    }

    @Override
    public String getDescription() {
        return getMessages().getString("fuzz.description");
    }

    @Override
    public List<String> getActiveActions() {
        List<Fuzzer<?>> activeFuzzers = fuzzersController.getActiveScans();
        if (activeFuzzers.isEmpty()) {
            return null;
        }

        String activeActionPrefix = getMessages().getString("fuzz.activeActionPrefix");
        List<String> activeActions = new ArrayList<>(activeFuzzers.size());
        for (Fuzzer<?> activeFuzzer : activeFuzzers) {
            activeActions.add(
                    MessageFormat.format(activeActionPrefix, activeFuzzer.getDisplayName()));
        }
        return activeActions;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void destroy() {
        super.destroy();

        fuzzersController.stopAllScans();
    }

    private ZapMenuItem getMenuItemCustomScan() {
        if (menuItemCustomScan == null) {
            menuItemCustomScan =
                    new ZapMenuItem(
                            "fuzz.menu.tools.fuzz",
                            getView()
                                    .getMenuShortcutKeyStroke(
                                            KeyEvent.VK_F, KeyEvent.ALT_DOWN_MASK, false));

            menuItemCustomScan.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent e) {
                            fuzzerStarter.actionPerformed(e);
                        }
                    });
        }

        return menuItemCustomScan;
    }

    private void readFuzzersDir() {
        Path fuzzerDirectory = Paths.get(Constant.getInstance().FUZZER_DIR);
        if (!Files.isDirectory(fuzzerDirectory)) {
            fuzzersDir = new FuzzersDir(Collections.<FuzzerPayloadCategory>emptyList());
            return;
        }

        try {
            Files.walkFileTree(
                    fuzzerDirectory,
                    Collections.<FileVisitOption>emptySet(),
                    Integer.MAX_VALUE,
                    new SimpleFileVisitor<Path>() {

                        private final Deque<ArrayList<FuzzerPayloadCategory>> directories =
                                new ArrayDeque<>();
                        private final Deque<ArrayList<FuzzerPayloadSource>> files =
                                new ArrayDeque<>();
                        private final List<String> categoryNames = new ArrayList<>();
                        private int depth;

                        @Override
                        public FileVisitResult preVisitDirectory(
                                Path dir, BasicFileAttributes attrs) throws IOException {
                            if (dir.getFileName().toString().startsWith("docs")) {
                                return FileVisitResult.SKIP_SUBTREE;
                            }

                            if (depth != 0) {
                                categoryNames.add(dir.getFileName().toString());
                            }
                            directories.push(new ArrayList<FuzzerPayloadCategory>());
                            files.push(new ArrayList<FuzzerPayloadSource>());

                            depth++;
                            return super.preVisitDirectory(dir, attrs);
                        }

                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                                throws IOException {
                            String fileName =
                                    file.getFileName().toString().toLowerCase(Locale.ROOT);
                            if (depth == 1
                                    || (fileName.endsWith(".txt")
                                            && !fileName.startsWith("_")
                                            && !fileName.startsWith("readme"))) {
                                files.peek().add(new FuzzerPayloadFileSource(file));
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                                throws IOException {
                            if (depth == 1) {
                                ArrayList<FuzzerPayloadCategory> categories = directories.pop();
                                // Include custom files in "Custom" category.
                                categories.add(0, createCustomFuzzerFilesCategory(files.pop()));
                                // Include/handle JBroFuzz fuzzers as normal categories.
                                categories.add(fuzzerPayloadJBroFuzzCategory);

                                fuzzersDir = new FuzzersDir(categories);
                            } else {
                                List<FuzzerPayloadCategory> childDirs = directories.pop();
                                List<FuzzerPayloadSource> childFiles = files.pop();
                                if (!childDirs.isEmpty() || !childFiles.isEmpty()) {
                                    directories
                                            .peek()
                                            .add(
                                                    new FuzzerPayloadCategory(
                                                            dir.getFileName().toString(),
                                                            createSubCategoryFullName(
                                                                    categoryNames),
                                                            childDirs,
                                                            childFiles));
                                }
                            }
                            if (depth > 1) {
                                categoryNames.remove(categoryNames.size() - 1);
                            }
                            depth--;
                            return super.postVisitDirectory(dir, exc);
                        }
                    });
        } catch (IOException e) {
            LOGGER.warn("Failed to read all custom file fuzzers:", e);
        }

        if (fuzzOptionsPanel != null) {
            fuzzOptionsPanel.setFuzzersDir(fuzzersDir);
        }
        notifyFuzzersDirChanged();
    }

    private static String createSubCategoryFullName(List<String> categories) {
        if (categories == null || categories.size() == 0) {
            return "";
        }
        if (categories.size() == 1) {
            return categories.iterator().next();
        }

        StringBuilder strBuilder = new StringBuilder(categories.size() * 16);
        for (String category : categories) {
            if (strBuilder.length() > 0) {
                strBuilder.append(" / ");
            }
            strBuilder.append(category);
        }
        return strBuilder.toString();
    }

    public FuzzersDir getFuzzersDir() {
        return fuzzersDir;
    }

    private class FuzzerFilesUpdater implements AddonFilesChangedListener {

        @Override
        public void filesAdded() {
            updateFiles();
        }

        @Override
        public void filesRemoved() {
            updateFiles();
        }

        private void updateFiles() {
            readFuzzersDir();
        }
    }

    public <M extends Message, F extends Fuzzer<M>> void addFuzzerHandler(
            FuzzerHandler<M, F> fuzzerHandler) {
        fuzzerHandlers.add(fuzzerHandler);

        if (defaultFuzzerHandler == null) {
            defaultFuzzerHandler = fuzzerHandler;
        }

        if (fuzzerStarter != null) {
            fuzzerStarter.setEnabled(true);
        }
    }

    public void removeFuzzerHandler(FuzzerHandler<?, ?> fuzzerHandler) {
        if (fuzzerHandlers.remove(fuzzerHandler)) {
            fuzzersController.removeAllScans(fuzzerHandler);
        }

        if (defaultFuzzerHandler == fuzzerHandler) {
            if (fuzzerHandlers.isEmpty()) {
                defaultFuzzerHandler = null;
            } else {
                defaultFuzzerHandler = fuzzerHandlers.get(0);
            }
        }

        if (fuzzerStarter != null) {
            fuzzerStarter.setEnabled(!fuzzerHandlers.isEmpty());
        }
    }

    /**
     * Sets the default fuzzer handler shown when starting a fuzzer from the "Fuzzer" panel.
     *
     * <p>The calls to this method has no effect if the given {@code fuzzerHandler} was not
     * previously registered.
     *
     * @param fuzzerHandler the fuzzer handler that should be default fuzzer handler
     * @throws IllegalArgumentException if the given {@code fuzzerHandler} is {@code null}.
     * @see #addFuzzerHandler(FuzzerHandler)
     */
    public void setDefaultFuzzerHandler(FuzzerHandler<?, ?> fuzzerHandler) {
        if (fuzzerHandler == null) {
            throw new IllegalArgumentException("Parameter fuzzerHandler must not be null.");
        }
        if (fuzzerHandlers.contains(fuzzerHandler)) {
            defaultFuzzerHandler = fuzzerHandler;
        }
    }

    protected boolean hasFuzzerHandlers() {
        return !fuzzerHandlers.isEmpty();
    }

    protected <M extends Message, F extends Fuzzer<M>> FuzzerHandler<M, F> getFuzzHandler(
            MessageContainer<M> invoker) {
        for (FuzzerHandler<?, ?> fuzzerHandler : fuzzerHandlers) {
            if (fuzzerHandler.canHandle(invoker)) {
                try {
                    @SuppressWarnings("unchecked")
                    FuzzerHandler<M, F> fh = (FuzzerHandler<M, F>) fuzzerHandler;
                    return fh;
                } catch (ClassCastException e) {
                    LOGGER.warn(
                            "FuzzerHandler not consistent with required message type: "
                                    + fuzzerHandler.getClass().getCanonicalName());
                }
            }
        }
        return null;
    }

    public FuzzerOptions getDefaultFuzzerOptions() {
        return new FuzzerOptions(
                fuzzOptions.getDefaultThreadsPerFuzzer(),
                fuzzOptions.getDefaultRetriesOnIOError(),
                fuzzOptions.getDefaultMaxErrorsAllowed(),
                fuzzOptions.getDefaultFuzzDelayInMs(),
                TimeUnit.MILLISECONDS,
                fuzzOptions.getDefaultPayloadReplacementStrategy());
    }

    protected <M extends Message, F extends Fuzzer<M>> void showFuzzerDialog(
            FuzzerHandler<M, F> fuzzerHandler,
            SelectableContentMessageContainer<M> messageContainer) {
        F fuzzer = fuzzerHandler.showFuzzerDialog(messageContainer, getDefaultFuzzerOptions());
        if (fuzzer == null) {
            return;
        }

        fuzzersController.registerScan(fuzzerHandler, fuzzer);
        fuzzer.run();

        fuzzScansPanel.scannerStarted(fuzzer);
        fuzzScansPanel.setTabFocus();
    }

    public <M extends Message, F extends Fuzzer<M>> void runFuzzer(
            FuzzerHandler<M, F> fuzzerHandler, F fuzzer) {
        fuzzersController.registerScan(fuzzerHandler, fuzzer);
        fuzzer.run();

        fuzzScansPanel.scannerStarted(fuzzer);
        fuzzScansPanel.setTabFocus();
    }

    protected <M extends Message, F extends Fuzzer<M>> void showFuzzerDialog(
            FuzzerHandler<M, F> fuzzerHandler, MessageContainer<M> messageContainer) {
        F fuzzer = fuzzerHandler.showFuzzerDialog(messageContainer, getDefaultFuzzerOptions());
        if (fuzzer == null) {
            return;
        }

        fuzzersController.registerScan(fuzzerHandler, fuzzer);
        fuzzer.run();

        fuzzScansPanel.scannerStarted(fuzzer);
        fuzzScansPanel.setTabFocus();
    }

    protected <M extends Message, F extends Fuzzer<M>> void showFuzzerDialog(
            FuzzerHandler<M, F> fuzzerHandler, M message) {
        F fuzzer = fuzzerHandler.showFuzzerDialog(message, getDefaultFuzzerOptions());
        if (fuzzer == null) {
            return;
        }

        fuzzersController.registerScan(fuzzerHandler, fuzzer);
        fuzzer.run();

        fuzzScansPanel.scannerStarted(fuzzer);
        fuzzScansPanel.setTabFocus();
    }

    /**
     * Gets the fuzzers of the given type.
     *
     * @param fuzzerClass the type of the fuzzer
     * @return a {@code List} containing all the fuzzers of the given type, never {@code null}
     */
    public <T1 extends Message, T2 extends Fuzzer<T1>> List<T2> getFuzzers(Class<T2> fuzzerClass) {
        return fuzzersController.getFuzzers(fuzzerClass);
    }

    /**
     * A {@code SessionChangedListener} responsible to stop all fuzzers when the session is about to
     * change and update the state of fuzzers panel when the session is about to change an when
     * there's change in mode and scope.
     */
    private class FuzzerSessionListener implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            fuzzersController.stopAllScans();
            if (fuzzScansPanel != null) {
                fuzzScansPanel.reset();
            }
        }

        @Override
        public void sessionChanged(Session session) {}

        @Override
        public void sessionScopeChanged(Session session) {
            if (fuzzScansPanel != null) {
                fuzzScansPanel.sessionScopeChanged(session);
            }
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            if (fuzzScansPanel != null) {
                fuzzScansPanel.sessionModeChanged(mode);
            }
        }
    }

    private class CustomFileFuzzerAddedListener
            implements FuzzOptionsPanel.CustomFileFuzzerAddedListener {

        @Override
        public void added(Path file) {
            addCustomFileFuzzer(file);
        }
    }

    private class FuzzerUIStarterAction extends AbstractAction {

        private static final long serialVersionUID = -636597626543120727L;

        private static final String NO_FUZZERS_TOOL_TIP_KEY =
                "fuzz.toolbar.button.new.tooltipNoFuzzers";

        public FuzzerUIStarterAction() {
            super(getMessages().getString("fuzz.toolbar.button.new"), FuzzerUIUtils.FUZZER_ICON);

            super.setEnabled(false);
            setToolTipText(getMessages().getString(NO_FUZZERS_TOOL_TIP_KEY));
        }

        @Override
        public void setEnabled(boolean enabled) {
            if (isEnabled() != enabled) {
                super.setEnabled(enabled);
                String toolTip;
                if (enabled) {
                    toolTip = null;
                } else {
                    toolTip = getMessages().getString(NO_FUZZERS_TOOL_TIP_KEY);
                }
                setToolTipText(toolTip);
            }
        }

        private void setToolTipText(String toolTip) {
            putValue(SHORT_DESCRIPTION, toolTip);
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            SelectMessageDialogue selectMessageDialogue =
                    new SelectMessageDialogue(
                            getView().getMainFrame(),
                            defaultFuzzerHandler.getUIName(),
                            fuzzerHandlers);
            selectMessageDialogue.pack();
            selectMessageDialogue.setVisible(true);

            showFuzzerDialogHelper(selectMessageDialogue.getSelection());
        }

        private <M extends Message, F extends Fuzzer<M>> void showFuzzerDialogHelper(
                SelectMessageDialogue.Selection<M, F> selection) {
            if (selection == null) {
                return;
            }
            showFuzzerDialog(selection.getFuzzerHandler(), selection.getMessage());
        }
    }

    public void addCustomFileFuzzer(Path file) {
        if (file == null) {
            return;
        }
        String fileName = file.getFileName().toString();
        for (FuzzerPayloadSource customFile :
                fuzzersDir.getCategories().get(0).getFuzzerPayloadSources()) {
            if (fileName.equals(customFile.getName())) {
                return;
            }
        }
        List<FuzzerPayloadCategory> newCategories = new ArrayList<>(fuzzersDir.getCategories());
        FuzzerPayloadCategory customFuzzerFilesCategory = newCategories.remove(0);

        List<FuzzerPayloadSource> customFiles =
                new ArrayList<>(customFuzzerFilesCategory.getFuzzerPayloadSources().size() + 1);
        customFiles.addAll(customFuzzerFilesCategory.getFuzzerPayloadSources());
        customFiles.add(new FuzzerPayloadFileSource(file));

        newCategories.add(0, createCustomFuzzerFilesCategory(customFiles));

        fuzzersDir = new FuzzersDir(newCategories);
        notifyFuzzersDirChanged();
    }

    private void notifyFuzzersDirChanged() {
        if (fuzzersDirChangeListeners != null) {
            for (FuzzersDirChangeListener listener : getFuzzersDirChangeListeners()) {
                listener.fuzzersDirChanged(fuzzersDir);
            }
        }
    }

    public void addFuzzersDirChangeListener(FuzzersDirChangeListener listener) {
        if (listener == null || getFuzzersDirChangeListeners().contains(listener)) {
            return;
        }
        getFuzzersDirChangeListeners().add(listener);
    }

    public void removeFuzzersDirChangeListener(FuzzersDirChangeListener listener) {
        if (listener == null || fuzzersDirChangeListeners == null) {
            return;
        }
        getFuzzersDirChangeListeners().remove(listener);
    }

    private List<FuzzersDirChangeListener> getFuzzersDirChangeListeners() {
        if (fuzzersDirChangeListeners == null) {
            createFuzzersDirChangeListeners();
        }
        return fuzzersDirChangeListeners;
    }

    private synchronized void createFuzzersDirChangeListeners() {
        if (fuzzersDirChangeListeners == null) {
            fuzzersDirChangeListeners = new ArrayList<>(2);
        }
    }

    public interface FuzzersDirChangeListener {

        void fuzzersDirChanged(FuzzersDir fuzzersDir);
    }
}
