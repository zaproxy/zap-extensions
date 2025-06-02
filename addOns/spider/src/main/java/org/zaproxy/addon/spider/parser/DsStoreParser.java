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
package org.zaproxy.addon.spider.parser;

import io.kaitai.struct.ByteBufferKaitaiStream;
import java.util.HashSet;
import java.util.Set;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.spider.parser.internal.DsStore;
import org.zaproxy.addon.spider.parser.internal.DsStore.Block;
import org.zaproxy.addon.spider.parser.internal.DsStore.Block.BlockData;
import org.zaproxy.addon.spider.parser.internal.DsStore.MasterBlockRef;
import org.zaproxy.addon.spider.parser.internal.DsStore.MasterBlockRef.MasterBlock;

/**
 * The Class DsStoreParser is used for parsing .DS_Store data.
 *
 * @author kingthorin
 */
public class DsStoreParser extends SpiderParser {

    private static final byte[] MAGIC_BYTES = {0, 0, 0, 1};

    @Override
    public boolean parseResource(ParseContext ctx) {
        if (!ctx.getSpiderParam().isParseDsStore()) {
            return false;
        }

        HttpMessage message = ctx.getHttpMessage();
        getLogger().debug("Parsing a .DS_Store: {}", message.getRequestHeader().getURI());

        if (message.getResponseHeader().getStatusCode() != HttpStatusCode.OK
                || message.getResponseBody().length() == 0) {
            return false;
        }

        DsStore dsStore = null;
        try {
            dsStore =
                    new DsStore((new ByteBufferKaitaiStream(message.getResponseBody().getBytes())));
        } catch (Exception ex) {
            getLogger().debug(ex.getMessage());
            return false;
        }
        for (MasterBlockRef masterBlockRef : dsStore.buddyAllocatorBody().directories()) {
            // Each B-tree directory has one master block comprising metadata.
            MasterBlock masterBlock = masterBlockRef.masterBlock();
            getLogger().debug("Records: {}", masterBlock.numRecords());

            Block rootBlock = masterBlock.rootBlock();

            // Traverse recursively the B-tree from its root block.
            try {
                traverse(rootBlock, ctx);
            } catch (Exception e) {
                getLogger().warn("There was an issue parsing the .DS_Store. {}", e.getMessage());
                getLogger().debug(e, e);
            }
        }

        // We consider the message fully parsed, so it doesn't get parsed by 'fallback' parsers
        return true;
    }

    private void traverse(Block block, ParseContext ctx) throws Exception {
        getLogger().debug("Traversing");
        Block nextBlock = block.rightmostBlock();

        if (nextBlock != null) {
            traverse(nextBlock, ctx);
        }

        Set<String> alreadyChecked = new HashSet<>();
        for (BlockData blockData : block.data()) {
            nextBlock = blockData.block();

            if (nextBlock != null) {
                getLogger().debug("Recursed");
                traverse(nextBlock, ctx);
            }
            String entry = blockData.record().filename().value();
            if (alreadyChecked.contains(entry)) {
                getLogger().debug("{} already done", entry);
                continue;
            }
            alreadyChecked.add(entry);
            getLogger().debug("Processing: {}", entry);
            processUrl(ctx, entry);
        }
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyParsed) {
        return ctx.getPath().endsWith(".DS_Store")
                && startsWith(ctx.getHttpMessage().getResponseBody().getBytes(), MAGIC_BYTES);
    }

    private static boolean startsWith(byte[] array, byte[] prefix) {
        if (array == prefix) {
            return true;
        }
        if (array == null || prefix == null || prefix.length > array.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (array[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
