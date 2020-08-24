/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HttpMessage;

/**
 * parse Git metadata to the degree necessary to extract source code from it
 *
 * @author 70pointer@gmail.com
 */
public class GitMetadata {

    /** the logger object */
    private static Logger log = Logger.getLogger(GitMetadata.class);

    /**
     * a pattern used to determine if a given SHA1 value is valid (from the point of view of the
     * format of the value)
     */
    final Pattern sha1pattern = Pattern.compile("[0-9a-f]{20}");

    /** a pattern used to determine the base folder for a Git file (ie, the ".git" folder path) */
    final Pattern basefolderpattern = Pattern.compile("^(.*/.git/)[^/]*$");

    /** the size of buffer to use when inflating deflated Git data */
    private int inflateBufferSize;

    /** used to send messages, and notify Zap that new messages have been sent */
    private HostProcess parent = null;

    /**
     * store off the URIs that were requested to get the source code disclosure for instance:
     * http://www.example.com/.git/index - the list of files in the repo
     * http://www.example.com/.git/objects/49/a7eca74dfebcaba00ea5eee60dcff7918f930c - an example
     * unpacked (aka "loose") file in the objects directory
     * http://www.example.com/.git/objects/info/packs - contains the name of the pack file and index
     * file
     * http://www.example.com/.git/objects/pack/pack-ae0d45afdff3d83a8b724294aa33e617c5e3dce9.idx -
     * an example pack index file
     * http://www.example.com/.git/objects/pack/pack-ae0d45afdff3d83a8b724294aa33e617c5e3dce9.pack -
     * an example pack data file
     */
    private String urisUsed = null;

    /** how many URIs have we recorded so far? */
    private int uriCount = 0;

    private int tempbytesread;

    /**
     * gets the Git URIs that were successfully queried to get the Source Code Disclosure
     *
     * @return
     */
    public String getGitURIs() {
        return urisUsed;
    }

    public GitMetadata(HostProcess hostprocess, int inflateBufferSize) {
        this.parent = hostprocess;
        this.inflateBufferSize = inflateBufferSize;
    }

    /**
     * inflate the byte array, using the specified buffer size
     *
     * @param data the data to inflate
     * @param buffersize the buffer size to use when inflating the data
     * @return the inflated data
     * @throws Exception
     */
    protected byte[] inflate(byte[] data, int buffersize) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(data);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
        byte[] buffer = new byte[buffersize];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            outputStream.write(buffer, 0, count);
        }
        outputStream.close();
        inflater.end();
        return outputStream.toByteArray();
    }

    /**
     * get the URL contents, from a local cache, if possible. Only a HTTP 200 error code is
     * considered a success. Redirects are not automatically followed.
     *
     * @param url the URL to request
     * @param inflate whether to interpret the results as deflated, and inflate them
     * @return the URI contents, inflated, if requested. If the HTTP response code != 200, returns
     *     NULL
     * @throws Exception
     */
    protected byte[] getURIResponseBody(URI uri, boolean inflate, HttpMessage basemsg)
            throws Exception {
        byte[] data = null;
        if (log.isDebugEnabled()) log.debug("Debug: Requesting URI '" + uri + "'");

        // set a limit of 20 Git URIs to be followed for a single URI
        uriCount++;
        if (uriCount > 20) {
            throw new Exception(
                    "Too many Git URLs requested for this URI: " + uriCount + ". Aborting");
        }
        // TODO: split out the Git MetaData from the SourceCodeDisclosure class (not as a nested
        // class)
        MessageCache messagecache = MessageCache.getSingleton(parent);
        HttpMessage msg = messagecache.getMessage(uri, basemsg, false);

        if (msg.getResponseHeader().getStatusCode() != HttpStatus.SC_OK) {
            throw new FileNotFoundException(uri.getURI());
        }
        // record the URI if it came back with a 200 (see the condition above)
        if (this.urisUsed == null || this.urisUsed.equals("")) this.urisUsed = uri.getURI();
        else this.urisUsed = this.urisUsed + ", " + uri.getURI();
        data = msg.getResponseBody().getBytes();

        if (inflate) {
            return inflate(data, inflateBufferSize);
        } else return data;
    }

    /**
     * get data for a given SHA1 object, trying both the unpacked (loose) and packed formats
     *
     * @param basemsg the base message to use when retrieving additional resources
     * @param gitbasepath the Git base path
     * @param filesha1 the SHA1 associated with the file in Git
     * @return the binary data associated with the file in Git, as specified by the filesha1
     *     parameter
     * @throws Exception
     */
    public byte[] getObjectData(HttpMessage basemsg, String gitbasepath, String filesha1)
            throws Exception {
        // try the unpacked first, cos it's simpler and quicker. (It might not be the common case,
        // however)
        // but if that fails, try to get the data from the packed files.
        try {
            return getObjectData(basemsg, gitbasepath, filesha1, false);
        } catch (FileNotFoundException e) {
            // try the packed format instead
            if (log.isDebugEnabled())
                log.debug(
                        "An unpacked file was not found for SHA1 "
                                + filesha1
                                + ". Trying for a packed file instead");

            // and re-initialise the URIs that we record, because the file in unpacked format did
            // not work out for us
            this.uriCount = 0;
            return getObjectData(basemsg, gitbasepath, filesha1, true);
        }
    }

    /**
     * get data for a given SHA1 object, using either the loose or packed formats
     *
     * @param basemsg the base message to use when retrieving additional resources
     * @param gitbasepath the Git base path
     * @param filesha1 the SHA1 associated with the file in Git
     * @param trypacked try the packed format, or try the loose format
     * @return the binary data associated with the file in Git, as specified by the filesha1
     *     parameter
     * @throws Exception
     */
    public byte[] getObjectData(
            HttpMessage basemsg, String gitbasepath, String filesha1, boolean trypacked)
            throws Exception {

        URI originaluri = basemsg.getRequestHeader().getURI();
        if (!trypacked) {
            // try the unpacked (loose) format
            URI gitobjecturi =
                    new URI(
                            originaluri.getScheme(),
                            originaluri.getAuthority(),
                            gitbasepath
                                    + "objects/"
                                    + filesha1.substring(0, 2)
                                    + "/"
                                    + filesha1.substring(2),
                            null,
                            null);

            if (log.isDebugEnabled())
                log.debug("The internal Git (loose) file name is " + gitobjecturi.getURI());
            byte[] data = getURIResponseBody(gitobjecturi, true, basemsg);

            ByteBuffer dataBuffer = ByteBuffer.wrap(data);
            StringBuilder sb = new StringBuilder();
            while (true) {
                byte b = dataBuffer.get();
                if (b == ' ') break;
                sb.append((char) b);
            }
            String objecttype = new String(sb);
            if (!objecttype.equals("blob")) {
                throw new Exception(
                        "The Git 'loose' file '"
                                + gitobjecturi
                                + "' is not of type 'blob': '"
                                + objecttype
                                + "'");
            }
            // read the size of data in the file (which appears as ASCII digits in the text), until
            // we get a 0x00
            sb = new StringBuilder();
            while (true) {
                byte b = dataBuffer.get();
                if (b == 0x00) break;
                sb.append((char) b);
            }
            int dataSize = Integer.parseInt(new String(sb));

            // now read that number of bytes from the bytebuffer, or at least attempt to..
            byte[] blobDecoded = new byte[dataSize];
            dataBuffer.get(blobDecoded);
            // that's it. we're done. return the decoded data, which will hopefully be source code
            // :)
            return blobDecoded;
        } else {
            // try the packed format

            // With the Git "packed" format, there are Git "pack index" files, and Git "pack" files.
            // They come as a set. You need both to get the contents of the file you're looking for.
            // The name of the Git "pack" files and "pack index" files is based on the SHA1 sum of
            // the SHA1 objects that it contains, and is not guessable.
            // This is an issue if you do not already know what pack files live in the directory
            // (unless you have a directory listing, for instance).
            // Luckily, in practice, in most cases (although not always) the name of the "pack" file
            // is contained in an ".git/objects/info/packs" file in the Git repo metadata.
            // The ".git/objects/info/packs" can also contain the names of multiple pack files,
            // which I have not seen in practice. That scenario is not currently supported here.

            // Both the "pack" and "pack index" files have an associated version number, but not
            // necessarily the same version number as each other.
            // There are constraints and interdependencies on these version numbers, however.

            // The Git "pack index" file currently comes in versions 1,2, and 3 (as of January 30,
            // 2014).

            // version 1 "pack index" files are not seen in the wild, but can be created using later
            // versions of Git, if necessary.  Version 1 is supported here.
            //				(Version 1 "pack index" files are seen in conjunction with Version 2 "pack" files,
            // but there is no reason (that I know of) why they should not also support Version 3 or
            // 4 pack files).
            // version 2 "pack index" files use either a version 2 or version 3 "pack" file. All
            // these versions are supported here.
            //    			(Version 1 and 2 "pack index" file formats have structural differences, but not
            // not wildly dis-similar).
            // version 3 "pack index" file cannot yet be created by any currently known version of
            // Git, but the format is documented.
            //				(Version 3 "pack index" files require a version 4 "pack file". Both these versions
            // are tentatively supported here, although this code has never been tested)

            // The Git "pack" file currently comes in versions 1,2,3, and 4 (as of January 30,
            // 2014).
            // Version 1 "pack" files do not appear to be documented. They are not supported here.
            // Version 2 "pack files" are used with version 2 "pack index" files. This is a common
            // scenario in the wild. Both versions are supported here.
            // Version 3 "pack files" are (also) used with version 2 "pack index" files. Both
            // versions are supported here.
            //           (Version 3 "pack files" are identical in format to version 2, with only the
            // version number differing)
            // Version 4 "pack files" are used in conjunction with version 3 "pack index" files.
            // Both these versions are tentatively supported here, although this code has never been
            // tested.

            // There are also separate version numbers in the Git "index file" (unrelated to the
            // "pack index" files mentioned above), which are probably similarly inter-related.
            // I do not have a mapping of the Git version number (1.7.6 / 1.8.5, for instance) to
            // any of the the internal file version numbers that they create (by default) or
            // support. So sue me.

            URI uri =
                    new URI(
                            originaluri.getScheme(),
                            originaluri.getAuthority(),
                            gitbasepath + "objects/info/packs",
                            null,
                            null);

            if (log.isDebugEnabled())
                log.debug("The internal Git file containing the name of the pack file is " + uri);

            byte[] packinfofiledata = null;
            try {
                packinfofiledata = getURIResponseBody(uri, false, basemsg);
            } catch (FileNotFoundException e) {
                log.error(
                        "We could not read '"
                                + uri
                                + "' to get the name of the pack file containing the content: "
                                + e.getMessage());
                throw e;
            }
            ByteBuffer dataBuffer = ByteBuffer.wrap(packinfofiledata);
            StringBuilder sb = new StringBuilder();
            while (true) {
                byte b = dataBuffer.get();
                if (b == ' ') break;
                sb.append((char) b);
            }
            String objecttype = new String(sb);
            if (!objecttype.equals("P")) {
                throw new Exception("The pack info file is not of type 'P': '" + objecttype + "'");
            }

            // the file should  begin with "P ", and everything after that is the pack file name
            // (and exclude the 2 trailing newlines as well)
            // TODO: handle the case where this file contains the name of multiple pack files.
            // Currently, i have no test cases. Maybe in extremely large Git repositories?
            byte[] packfilenamebytes = new byte[packinfofiledata.length - 4];
            dataBuffer.get(packfilenamebytes);
            String packfilename = new String(packfilenamebytes);
            // validate that the file name looks like "pack*.pack"
            Matcher packfilenamematcher =
                    Pattern.compile("^pack-[0-9a-f]{40}\\.pack$").matcher(packfilename);
            if (!packfilenamematcher.find()) {
                throw new Exception(
                        "The pack file name '"
                                + packfilename
                                + "' does not match the expected pattern");
            }

            // Now generate the full name of the pack file, and the pack index.
            URI packuri =
                    new URI(
                            originaluri.getScheme(),
                            originaluri.getAuthority(),
                            gitbasepath + "objects/pack/" + packfilename,
                            null,
                            null);
            URI packindexuri =
                    new URI(
                            originaluri.getScheme(),
                            originaluri.getAuthority(),
                            gitbasepath
                                    + "objects/pack/"
                                    + packfilename.substring(0, packfilename.length() - 5)
                                    + ".idx",
                            null,
                            null);

            // retrieve the content for the "pack index" file!
            byte[] packfileindexdata = null;
            try {
                packfileindexdata = getURIResponseBody(packindexuri, false, basemsg);
            } catch (FileNotFoundException e) {
                System.out.println(
                        "We could not read '"
                                + packindexuri
                                + "', which is necessary to get the packed contents of the SHA1 requested: "
                                + e.getMessage());
                throw e;
            }

            // retrieve the content for the "pack" file!
            byte[] packfiledata = null;
            try {
                packfiledata = getURIResponseBody(packuri, false, basemsg);
            } catch (FileNotFoundException e) {
                System.out.println(
                        "We could not read '"
                                + packuri
                                + "', which should contain the packed contents of the SHA1 requested: "
                                + e.getMessage());
                throw e;
            }

            // now that we know we have both the "pack index" and the "pack" (data) file, parse the
            // data
            // first parse out some signature data info from the "pack" file
            ByteBuffer packfileheaderBuffer = ByteBuffer.wrap(packfiledata, 0, 12);
            byte[] packfileheaderSignatureArray = new byte[4]; // 4 bytes
            packfileheaderBuffer.get(packfileheaderSignatureArray);
            if (!new String(packfileheaderSignatureArray).equals("PACK")) {
                throw new Exception("The pack file header does not appear to be valid");
            }
            int packFileVersion = packfileheaderBuffer.getInt(); // 4 bytes
            int packEntryCount = packfileheaderBuffer.getInt(); // 4 bytes

            if (packFileVersion != 2 && packFileVersion != 3 && packFileVersion != 4) {
                throw new Exception(
                        "Only Git Pack File versions 2, 3, and 4 are currently supported. Git Pack File Version "
                                + packFileVersion
                                + " was found. Contact the zaproxy (OWASP Zap) dev team");
            }

            // for pack file version 4, read the SHA1 tables from the "pack" file at this point
            // these used to live in the "pack index" file, in earlier versions.
            // Note: since at this point in time, there is no way to generate a v3 pack index file +
            // v4 pack file
            // so this particular block of code remains hypothetical.  it seems to comply with the
            // documented version 4 "pack" file format, however, and it
            // works for version 2 "pack index" and version 2 "pack" files, which appears to be the
            // most common combination seen in the wild.

            int sha1Index = Integer.MAX_VALUE;
            int packEntryOffsetArray[] = null;
            int packEntryOffsetArrayOrdered[] = null;
            int indexEntryCount = 0;

            if (packFileVersion >= 4) {
                sha1Index = Integer.MAX_VALUE;
                // the tables in the V4 tables in the pack file are variable length, so just grab
                // the data after the main header for now
                ByteBuffer packfileTablesBuffer =
                        ByteBuffer.wrap(packfiledata, 12, packfiledata.length - 12);
                // read the series of 20 byte sha1 entries.
                // ours *should* be in here somewhere.. find it
                // make sure to read *all* of the entries from the file (or else seek to the end of
                // the data), so the parsing logic is not broken.
                // TODO: use a binary search to find this in a more efficient manner

                for (int i = 0; i < packEntryCount; i++) {
                    byte[] packTableData = new byte[20];
                    packfileTablesBuffer.get(packTableData);
                    String packTableSha1 = Hex.encodeHexString(packTableData);
                    // TODO: use more efficient byte based comparison to find the SHA1 here (and in
                    // similar code in pack index version 2 logic, later..
                    if (packTableSha1.equals(filesha1)) {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "FOUND our SHA1 "
                                            + packTableSha1
                                            + " at entry "
                                            + i
                                            + " in the v4 pack tables");
                        sha1Index = i;

                        // we do not need to "read past" all the entries.
                        break;
                    }
                }
            }

            // try to parse the "pack index" as a version 1 "pack index" file, which has a different
            // layout to subsequent versions.
            // use a separate ByteBuffer for this, in case things don't work out (because they
            // probably will not work out) :)
            try {
                ByteBuffer packindexfileV1dataBuffer = ByteBuffer.wrap(packfileindexdata);
                byte packEntrySizeArray[] = new byte[256 * 4];
                packindexfileV1dataBuffer.get(packEntrySizeArray);

                if (
                /*packEntrySizeArray[0]== 0xFF && */
                packEntrySizeArray[1] == 't'
                        && packEntrySizeArray[2] == 'O'
                        && packEntrySizeArray[3] == 'c') {
                    // the signature is a non-V1 signature.
                    throw new NotV1GitPackIndexFileException();
                }
                // get the last 4 bytes as an int, network order.
                indexEntryCount = (packEntrySizeArray[(255 * 4) + 3] << 0);
                indexEntryCount |= (packEntrySizeArray[(255 * 4) + 2] << 8);
                indexEntryCount |= (packEntrySizeArray[(255 * 4) + 1] << 16);
                indexEntryCount |= (packEntrySizeArray[(255 * 4) + 0] << 24);

                // validate that this matches the number of entries in the "pack" file.
                if (indexEntryCount != packEntryCount) {
                    throw new Exception(
                            "The entry count ("
                                    + indexEntryCount
                                    + ") from the version 1 pack index file does not match the entry count ("
                                    + packEntryCount
                                    + ") from the pack file ");
                }
                if (log.isDebugEnabled())
                    log.debug(
                            "Got a pack index entry count of "
                                    + indexEntryCount
                                    + " from the version 1 pack index file");

                // read the indexEntryCount * (4+20) byte entries (4 + 20 blackbirds baked in a
                // pie!)
                sha1Index = Integer.MAX_VALUE;
                packEntryOffsetArray = new int[indexEntryCount];
                packEntryOffsetArrayOrdered = new int[indexEntryCount];

                // TODO: use a binary search to find this in a more efficient manner
                for (int i = 0; i < indexEntryCount; i++) {
                    // read 4 bytes offset (the offset of the SHA1's data in the "pack" file)
                    packEntryOffsetArray[i] = packindexfileV1dataBuffer.getInt();
                    packEntryOffsetArrayOrdered[i] = packEntryOffsetArray[i];

                    // read 20 bytes SHA1
                    byte[] indexEntryIdBuffer = new byte[20];
                    packindexfileV1dataBuffer.get(indexEntryIdBuffer);
                    String indexEntrySha1 = Hex.encodeHexString(indexEntryIdBuffer);
                    if (indexEntrySha1.equals(filesha1)) {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "FOUND our SHA1 "
                                            + indexEntrySha1
                                            + " at entry "
                                            + i
                                            + " in the SHA1 table");
                        sha1Index = i;
                    }
                }
                // final sanity check, if all of the above panned out for version 1 index file.
                // Note: we *think* that that "pack index" file version 1 is compatible with "pack"
                // file version 3 and 4, but really, we don't know for sure.. Again, so sue me.
                int packindexFileVersion = 1;
                if (packFileVersion != 2 && packFileVersion != 3 && packFileVersion != 4) {
                    throw new Exception(
                            "Pack index file version ("
                                    + packindexFileVersion
                                    + ") is incompatible with pack file version ("
                                    + packFileVersion
                                    + ")");
                }

            } catch (NotV1GitPackIndexFileException e) {
                // so it's not a version 1 "pack index" file. Try parsing it as a version 2, 3, 4
                // (or later versions, once there are more versions, and we support them)
                if (log.isDebugEnabled())
                    log.debug(
                            "The 'pack index' file looks like a > version 1 'pack index' file. Trying to parse it as later formats instead");

                // Parse the "pack index" file header
                ByteBuffer packindexfiledataBuffer = ByteBuffer.wrap(packfileindexdata);

                byte[] packindexfileheaderSignatureArray = new byte[4];
                packindexfiledataBuffer.get(packindexfileheaderSignatureArray);
                if (
                /*packindexfileheaderSignatureArray[0]!= 0xFF || */
                packindexfileheaderSignatureArray[1] != 't'
                        || packindexfileheaderSignatureArray[2] != 'O'
                        || packindexfileheaderSignatureArray[3] != 'c') {
                    throw new Exception(
                            "The pack index file header does not appear to be valid for pack index file version 2, 3, or 4: '"
                                    + new String(packindexfileheaderSignatureArray)
                                    + "' was found");
                }

                // Note: version 1 is handled separately, so need to check for it here.
                int packindexFileVersion = packindexfiledataBuffer.getInt();
                if (packindexFileVersion != 2 && packindexFileVersion != 3) {
                    throw new Exception(
                            "Pack index file version("
                                    + packindexFileVersion
                                    + ") is not supported");
                }
                if ((packFileVersion == 2 || packFileVersion == 3) && packindexFileVersion != 2) {
                    throw new Exception(
                            "Pack index file version ("
                                    + packindexFileVersion
                                    + ") is incompatible with pack file version ("
                                    + packFileVersion
                                    + ")");
                }
                if (packindexFileVersion == 3 && packFileVersion != 4) {
                    throw new Exception(
                            "Pack index file version ("
                                    + packindexFileVersion
                                    + ") is only compatible with pack file version 4. Pack file version ("
                                    + packFileVersion
                                    + ") was found");
                }

                int packEntrySizeArray[] = new int[256];
                for (int i = 0; i < 256; i++) {
                    packEntrySizeArray[i] = packindexfiledataBuffer.getInt();
                }
                // get the total number of entries, as being the number of entries from the final
                // fanout table entry.
                indexEntryCount = packEntrySizeArray[255];
                // validate that this matches the number of entries in the pack file, according to
                // its header.
                if (indexEntryCount != packEntryCount) {
                    throw new Exception(
                            "The entry count ("
                                    + indexEntryCount
                                    + ") from the pack index does not match the entry count ("
                                    + packEntryCount
                                    + ") from the pack file");
                }

                // in version 3 of the pack index file, the SHA1 table moves from the pack index
                // file to the pack file (necessitating a version 4 pack file, as noted earlier)
                // in versions < 3 of the index file, the SHA1 data lives in the index file in some
                // manner (differs between version 1, and versions 2,3).
                if (packindexFileVersion < 3) {
                    sha1Index = Integer.MAX_VALUE;
                    // read the series of 20 byte sha1 entries.
                    // ours *should* be in here somewhere.. find it
                    // make sure to read *all* of the entries from the file (or else seek to the end
                    // of the data), so the parsing logic is not broken.
                    // TODO: use a binary search to find this in a more efficient manner

                    for (int i = 0; i < indexEntryCount; i++) {
                        byte[] indexEntryIdBuffer = new byte[20];
                        packindexfiledataBuffer.get(indexEntryIdBuffer);
                        String indexEntrySha1 = Hex.encodeHexString(indexEntryIdBuffer);
                        if (indexEntrySha1.equals(filesha1)) {
                            if (log.isDebugEnabled())
                                log.debug(
                                        "FOUND our SHA1 "
                                                + indexEntrySha1
                                                + " at entry "
                                                + i
                                                + " in the SHA11 table");
                            sha1Index = i;
                        }
                    }
                }
                // read the CRCs for the various entries (and throw them away, for now)
                byte[] crcs = new byte[indexEntryCount * 4];
                packindexfiledataBuffer.get(crcs);

                // read the offsets for the various entries. We need to know the offset into the
                // pack file of the SHA11 entry we are looking at
                // NB: the various tables in the "pack index" file are sorted by the corresponding
                // SHA1.
                // 2 adjacent entries in the offset table (for consequtive SHA11 entries) could have
                // wildly different offsets into the "pack" file
                // and the offsets in the table are therefore not sorted by offset.
                // In order to calculate the deflated length of an entry in the pack file (which is
                // not stored anywhere),
                // we need to generate an extra offset table, ordered by the offset. We will then
                // look for the next ordered offset, and store it alongside
                // the offset of the SHA1 we're interested in.
                packEntryOffsetArray = new int[indexEntryCount];
                packEntryOffsetArrayOrdered = new int[indexEntryCount];
                for (int i = 0; i < indexEntryCount; i++) {
                    packEntryOffsetArray[i] = packindexfiledataBuffer.getInt();
                    packEntryOffsetArrayOrdered[i] = packEntryOffsetArray[i];
                }
            }
            // now we're out of the pack index file version 1 or 2/3 specific stuff.. the rest of
            // the logic is fairly common (except for the "pack" file version 4 stuff, of course! :)
            Arrays.sort(packEntryOffsetArrayOrdered);

            // take account of the 20 byte sha1 checksum after all the individual entries
            int nextOffset = packfiledata.length - 20;
            // get the first offset greater than the offset of our sha1. since the table is ordered
            // by offset, these 2 offsets gives us the deflated length of the entry
            for (int i = 0; i < indexEntryCount; i++) {
                if (packEntryOffsetArrayOrdered[i] > packEntryOffsetArray[sha1Index]) {
                    nextOffset = packEntryOffsetArrayOrdered[i];
                    // if (log.isDebugEnabled()) log.debug("Found the entry with the next offset: "+
                    // nextOffset);
                    if (nextOffset > (packfiledata.length - 1))
                        throw new Exception(
                                "A 'next' offset of "
                                        + nextOffset
                                        + " is not feasible for a pack file with length "
                                        + packfiledata.length);
                    break;
                }
            }
            // given the "pack" file offsets, we know the deflated length of the entry in there.
            int entryLength = (nextOffset - packEntryOffsetArray[sha1Index]);
            if (log.isDebugEnabled()) {
                log.debug("Our offset into the pack file is " + packEntryOffsetArray[sha1Index]);
                log.debug("The offset of the next entry into the pack file is " + nextOffset);
                log.debug(
                        "The deflated entry length, based on offset differences, is "
                                + entryLength);
            }

            // get the data from the pack file and return it.
            byte[] inflatedData =
                    getPackedObjectData(
                            packfiledata,
                            packEntryOffsetArray[sha1Index],
                            entryLength,
                            packFileVersion);
            return inflatedData;
        }
    }

    /**
     * gets the data for the object in the pack file data with the version specified, at the
     * specified offset
     *
     * @param packfiledata byte array containing the raw data associated with the pack file
     * @param packfiledataoffset the offset for the specified intry into the raw pack file data
     * @param entryLength the deflated length of the packfile object entry
     * @param packFileVersion the version of the pack file. The version determines the file format,
     *     and thus the object extraction logic.
     * @return the inflated binary data associated with the entry extracted from the pack file
     * @throws Exception
     */
    private byte[] getPackedObjectData(
            byte[] packfiledata, int packfiledataoffset, int entryLength, int packFileVersion)
            throws Exception {

        try {
            // wrap the entry we are interested in in a ByteBuffer (using the offsets to calculate
            // the length)
            // Note: the offset is from the start of the "pack" file, not from after the header.
            if (packfiledataoffset > (packfiledata.length - 1)) {
                throw new Exception(
                        "The offset "
                                + packfiledataoffset
                                + " into the pack file is not valid given pack file data length:"
                                + packfiledata.length);
            }
            if ((packfiledataoffset + entryLength) > packfiledata.length) {
                throw new Exception(
                        "The offset "
                                + packfiledataoffset
                                + " into the pack file and the entry length "
                                + entryLength
                                + " is not valid given pack file data length:"
                                + packfiledata.length);
            }
            ByteBuffer entryBuffer = ByteBuffer.wrap(packfiledata, packfiledataoffset, entryLength);
            byte typeandsize = entryBuffer.get(); // size byte #1: 4 bits of size data available
            // get bits 6,5,4 into a byte, as the least significant bits. So if  typeandsize =
            // bXYZbbbbb, then entryType = 00000XYZ
            // TODO: there may be a change required here for version 4 "pack" files, which use a 4
            // bit type, rather than a 3 bit type in earlier versions.
            // but maybe not, because we only handle one type (for blobs), which probably does not
            // set the highest bit in the "type" nibble.
            // The valid Object Type Bit Patterns for Version 2/3 are
            // #	000	- invalid: Reserved
            // #	001	- COMMIT object
            // #	010	- TREE object
            // #	011	- BLOB object
            // #	100	- TAG object
            // #	101	- invalid: Reserved
            // #	110	- DELTA_ENCODED object w/ offset to base
            // #	111	- DELTA_ENCODED object w/ base BINARY_OBJ_ID
            byte entryType = (byte) ((typeandsize & (byte) 0x70) >> 4);
            if (log.isDebugEnabled()) log.debug("The pack file entry is of type " + entryType);

            if (entryType == 0x7) {
                // TODO :support Packed Objects of type 'DELTA_ENCODED object with base
                // BINARY_OBJ_ID'
                throw new Exception(
                        "Packed Objects of type 'DELTA_ENCODED object with base BINARY_OBJ_ID' are not yet supported. If you have a test case, please let the OWASP Zap dev team know!");
            }

            // Note that 0x7F is 0111 1111 in binary. Useful to mask off all but the top bit of a
            // byte
            // and that 0x80 is 1000 0000 in binary. Useful to mask off the lower bits of a byte
            // and that 0x70 is 0111 0000 in binary. Used above to mask off 3 bits of a byte
            // and that  0xF is 0000 1111 in binary.

            // get bits 2,1,0 into a byte, as the least significant bits. So if  typeandsize =
            // bbbbbbXYZ, then entrySizeNibble = 00000XYZ
            // get the lower 4 bits of the byte as the first size byte
            byte entrySizeNibble = (byte) ((typeandsize & (byte) 0xF));
            int entrySizeWhenInflated = (int) entrySizeNibble;

            // set up to check if the "more" flag is set on the entry+size byte, then look at the
            // next byte for size..
            byte nextsizebyte = (byte) (typeandsize & (byte) 0x80);

            // the next piece of logic decodes the variable length "size" information, which comes
            // in an initial 4 bit, followed by potentially multiple additional 7 bit chunks.
            // (3 bits type for versions < 4, or 4 bits for version 4 "pack" files)
            int sizebytescounted = 1;
            while ((nextsizebyte & 0x80) > 0) {
                // top bit is set on nextsizebyte, so we need to get the next byte as well
                if (sizebytescounted > 4) {
                    // this should not happen. the size should be determined by a max of 4 bytes.
                    throw new Exception(
                            "The number of entry size bytes read exceeds 4. Either data corruption, or a parsing error has occurred");
                }
                nextsizebyte = entryBuffer.get();
                entrySizeWhenInflated =
                        ((((nextsizebyte & 0x7F)) << (4 + (7 * (sizebytescounted - 1))))
                                | entrySizeWhenInflated);
                sizebytescounted++;
            }

            // handle each object type
            byte[] inflatedObjectData = null;
            if (entryType == 0x0) {
                throw new Exception("Invalid packed Git Object type 0x0: Reserved");
            } else if (entryType == 0x5) {
                throw new Exception("Invalid packed Git Object type 0x5: Reserved");
            } else if (entryType == 0x1
                    || entryType == 0x2
                    || entryType == 0x3
                    || entryType == 0x4) {
                // for non-deltified objects - this is the simple and common case (in small
                // repositories, at least)
                // this includes Commits, Trees, Blobs, and Tags
                if (log.isDebugEnabled())
                    log.debug(
                            "The size of the un-deltified inflated entry should be "
                                    + entrySizeWhenInflated
                                    + ", binary: "
                                    + Integer.toBinaryString(entrySizeWhenInflated));

                // extract the data from the "pack" file, taking into account its total size, based
                // on the offsets, and the number of type and size bytes already read.
                int entryDataBytesToRead = entryLength - sizebytescounted;
                // if (log.isDebugEnabled()) log.debug("Read " + sizebytescounted + " size bytes, so
                // will read " + entryDataBytesToRead + " bytes of entry data from the 'pack'
                // file");

                byte deflatedSource[] = new byte[entryDataBytesToRead];
                entryBuffer.get(deflatedSource);
                // since it's undeltified, it's probably not a very big file, so no need to specify
                // a very large buffer size.
                inflatedObjectData = inflate(deflatedSource, 1024);
            } else if (entryType == 0x6) {
                // for 'DELTA_ENCODED object with offset to base'
                // this object type is not common in small repos. it will get more common in larger
                // Git repositorie.
                int deltabaseoffset = readBigEndianModifiedBase128Number(entryBuffer);
                int deltaoffsetBytesRead = this.tempbytesread;
                if (log.isDebugEnabled())
                    log.debug(
                            "DELTA_ENCODED object with offset to base: got a delta base offset of "
                                    + deltabaseoffset
                                    + ", by reading "
                                    + deltaoffsetBytesRead
                                    + " bytes");

                // the data after the delta base offset is deflated. so read it, inflate it, and
                // decode it.
                int deflatedDeltaDataBytesToRead =
                        entryLength - sizebytescounted - deltaoffsetBytesRead;
                byte deflatedDeltaData[] = new byte[deflatedDeltaDataBytesToRead];
                entryBuffer.get(deflatedDeltaData);
                byte[] inflatedDeltaData = inflate(deflatedDeltaData, 1024);

                ByteBuffer inflateddeltadataBuffer = ByteBuffer.wrap(inflatedDeltaData);

                // read the base object length and result object length as little-endian base 128
                // numbers from the inflated delta data
                int baseobjectlength = readLittleEndianBase128Number(inflateddeltadataBuffer);
                int resultobjectlength = readLittleEndianBase128Number(inflateddeltadataBuffer);

                // now that we have the offset into the pack data for the base object (relative to
                // the entry we're looking at),
                // and the length of the base object, go and get the base object
                // note that the base entry could be another deltified object, in which case, we
                // will need to recurse.
                if (log.isDebugEnabled())
                    log.debug(
                            "Getting a packed object from pack file offset "
                                    + packfiledataoffset
                                    + ", delta base offset "
                                    + deltabaseoffset
                                    + ", with inflated base object length "
                                    + deltabaseoffset
                                    + ", and deflated base object length "
                                    + baseobjectlength);
                // TODO: calculate the actual length of the entry for the base object.  This will be
                // <= deltabaseoffset, so for now, use that..
                // Note: this is an optimisation, rather than a functional issue..
                byte[] inflateddeltabasedata =
                        getPackedObjectData(
                                packfiledata,
                                packfiledataoffset - deltabaseoffset,
                                deltabaseoffset,
                                packFileVersion);
                if (inflateddeltabasedata.length != baseobjectlength) {
                    throw new Exception(
                            "The length of the delta base data extracted ("
                                    + inflateddeltabasedata.length
                                    + ") does not match the expected length ("
                                    + baseobjectlength
                                    + ")");
                }

                // apply the deltas from inflateddeltadataBuffer to inflateddeltabasedataBuffer, to
                // create an object of length resultobjectlength
                // now read the chunks, until there is no more data to be read
                while (inflateddeltadataBuffer.hasRemaining()) {
                    byte chunkByte = inflateddeltadataBuffer.get();
                    // log.debug("The delta chunk leading byte (in binary) is "+
                    // Integer.toBinaryString(chunkByte & 0xFF) );

                    if ((chunkByte & 0x80) == 0) {
                        // log.debug("The delta chunk leading byte indicates an INSERT");

                        // this is an insert chunk, so get its length
                        byte chunkInsertLength =
                                chunkByte; // the top bit is NOT set, so just use the entire
                        // chunkByte
                        if (chunkInsertLength < 0)
                            throw new Exception(
                                    "The insert chunk length ("
                                            + chunkInsertLength
                                            + ") should be positive.");
                        if (chunkInsertLength > inflateddeltadataBuffer.remaining())
                            throw new Exception(
                                    "The insert chunk requests "
                                            + chunkInsertLength
                                            + " bytes, but only "
                                            + inflateddeltadataBuffer.remaining()
                                            + " are available");
                        if (chunkInsertLength > resultobjectlength)
                            throw new Exception(
                                    "The insert chunk of length ("
                                            + chunkInsertLength
                                            + ") should be no bigger than the resulting object, which is of expected length ("
                                            + resultobjectlength
                                            + ")");

                        byte[] insertdata = new byte[chunkInsertLength];
                        inflateddeltadataBuffer.get(insertdata, 0, chunkInsertLength);
                        chunkByte = insertdata[insertdata.length - 1];

                        // if it passed the checks, append the insert chunk to the result buffer.
                        inflatedObjectData = ArrayUtils.addAll(inflatedObjectData, insertdata);
                    } else {
                        // log.debug("The delta chunk leading byte indicates a COPY");

                        // this is a copy chunk (where bit 7 is set on the byte)
                        // so bits 6-0 specify how the remainder of the chunk determine the copy
                        // base offset and length
                        int chunkCopyOffset = 0;
                        int chunkCopyLength = 0;
                        int bitshift = 0;

                        byte chunkCopyOpcode = chunkByte;

                        bitshift = 0;
                        for (int i = 0; i < 4; i++) {
                            // is the lsb set in the opcode (after we've shifted it right)?
                            if ((chunkCopyOpcode & 0x01) > 0) {
                                chunkByte = inflateddeltadataBuffer.get();
                                chunkCopyOffset |= ((((int) chunkByte & 0xFF) << bitshift));
                            }
                            chunkCopyOpcode >>= 1;
                            bitshift += 8;
                        }
                        // get the length
                        bitshift = 0;
                        // the length is determined by the pack file version. For Version 3, use 4
                        // bytes (0..3). For Version 2, use 3 bytes (0..2)
                        // support V3 as well here..
                        for (int i = 0;
                                i < (packFileVersion == 3 ? 3 : (packFileVersion == 2 ? 2 : 0));
                                i++) {
                            // is the lsb set in the opcode (after we've shifted it right)??
                            if ((chunkCopyOpcode & 0x01) > 0) {
                                chunkByte = inflateddeltadataBuffer.get();
                                chunkCopyLength |= ((((int) chunkByte & 0xFF) << bitshift));
                            }
                            chunkCopyOpcode >>= 1;
                            bitshift += 8;
                        }
                        if (chunkCopyLength == 0) {
                            chunkCopyLength = 1 << 16;
                        }
                        if (packFileVersion == 2) {
                            // Version 2 gave the ability to switch the source and target if a flag
                            // was set.
                            // we do not yet support it, because it doesn't seem to occur in the
                            // wild. If you have examples, please let us know!
                            boolean switchDirection = ((chunkCopyOpcode & 0x01) > 0);
                            if (switchDirection)
                                throw new Exception(
                                        "Git Pack File Version 2 chunk copy direction switching (copy from result) is not yet supported");
                        }

                        if (chunkCopyOffset < 0)
                            throw new Exception(
                                    "The copy chunk offset ("
                                            + chunkCopyOffset
                                            + ") should be positive.");
                        if (chunkCopyLength < 0)
                            throw new Exception(
                                    "The copy chunk length ("
                                            + chunkCopyLength
                                            + ") should be positive.");
                        if (chunkCopyLength > resultobjectlength)
                            throw new Exception(
                                    "The copy chunk of length ("
                                            + chunkCopyLength
                                            + ") should be no than the resulting object, which is of expected length ("
                                            + resultobjectlength
                                            + ")");
                        byte[] copydata = new byte[chunkCopyLength];
                        copydata =
                                Arrays.copyOfRange(
                                        inflateddeltabasedata,
                                        chunkCopyOffset,
                                        chunkCopyOffset + chunkCopyLength);

                        // if it passed the checks, append the copy chunk to the result buffer.
                        inflatedObjectData = ArrayUtils.addAll(inflatedObjectData, copydata);
                    }
                }
                // all the delta chunks have been handled
                return inflatedObjectData;
            }
            // validate that entrySizeWhenInflated == the actual size of the inflated data
            // there may not be much point in doing this, since the inflate will (in all
            // probability) fail if the length were wrong
            if (entrySizeWhenInflated != inflatedObjectData.length)
                throw new Exception(
                        "The predicted inflated length of the entry was "
                                + entrySizeWhenInflated
                                + ", when we inflated the entry, we got data of length "
                                + inflatedObjectData.length);

            return inflatedObjectData;
        } catch (Exception e) {
            log.error("Some error occurred extracting a packed object", e);
            throw e;
        }
    }

    /**
     * gets a Big Endian Modified Base 128 number from the Byte Buffer. This is a form of variable
     * length encoded int value.
     *
     * @param bb the ByteBuffer containing the data
     * @return an integer value
     */
    private int readBigEndianModifiedBase128Number(ByteBuffer bb) {
        int i = 0;

        this.tempbytesread = 0;
        byte b = bb.get();
        tempbytesread++;
        // get the lower 7 bits of b into i
        i = b & 0x7F;
        while ((b & 0x80) > 0) {
            // while the top bit of b is set (the "more" bit)
            // get another byte
            b = bb.get();
            tempbytesread++;
            // left shift i by 7 bits, making sure the top bit ends up being set, and bitwise OR
            // this with the lower 7 bits of i. Put the result in i.
            // in other words, left shift in 7 more bits of data from b into i!
            i = ((i + 1) << 7) | (b & 0x7F);
        }
        return i;
    }

    /**
     * gets a Little Endian Base 128 number from the Byte Buffer. This is a form of variable length
     * encoded int value.
     *
     * @param bb the ByteBuffer containing the data
     * @return an integer value
     */
    private int readLittleEndianBase128Number(ByteBuffer bb) {
        int i = 0;

        this.tempbytesread = 0;
        byte b = bb.get();
        tempbytesread++;
        // get the lower 7 bits of b into i
        i = b & 0x7F;
        while ((b & 0x80) > 0) {
            // while the top bit of b is set (the "more" bit)
            // get another byte
            b = bb.get();
            tempbytesread++;
            // left shift the lower 7 bits of b onto the left of the bits of data we have already
            // placed in i
            // i = ((i+1) <<7) | (b& 0x7F);
            i = ((b & 0x7F) << (7 * (tempbytesread - 1))) | i;
        }
        return i;
    }

    /**
     * gets a Map of relative file paths to SHA1s using raw Git index file data (which is not
     * verified here)
     *
     * @param data the raw binary data from a valid Git index file (Versions 2,3,4 are supported)
     * @return a Map of relative file paths to SHA1s using raw Git index file data
     * @todo consider sharing this method between the Git Spider, and the SourceCodeDisclosure scan
     *     rule.
     */
    @SuppressWarnings("unused")
    public Map<String, String> getIndexSha1s(byte[] data) throws Exception {
        Map<String, String> map = new TreeMap<String, String>();

        // wrap up the data, so we can read it..
        ByteBuffer dataBuffer = ByteBuffer.wrap(data);

        byte[] dircArray = new byte[4];
        dataBuffer.get(dircArray);

        int indexFileVersion = dataBuffer.getInt();
        // if ( log.isDebugEnabled() ) log.debug("The Git index file version is "+
        // indexFileVersion);

        int indexEntryCount = dataBuffer.getInt();
        // if ( log.isDebugEnabled() ) log.debug(indexEntryCount + " entries were found in the Git
        // index file ");

        if (indexFileVersion != 2 && indexFileVersion != 3 && indexFileVersion != 4) {
            throw new Exception(
                    "Only Git Index File versions 2, 3, and 4 are currently supported. Git Index File Version "
                            + indexFileVersion
                            + " was found.");
        }

        // for version 4 (and upwards?), we need to know the previous entry name, so store it
        String previousIndexEntryName = "";
        for (int entryIndex = 0; entryIndex < indexEntryCount; entryIndex++) {
            int entryBytesRead = 0;
            int indexEntryCtime1 = dataBuffer.getInt();
            entryBytesRead += 4;
            // if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has indexEntryCtime1
            // "+ indexEntryCtime1);
            int indexEntryCtime2 = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryMtime1 = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryMtime2 = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryDev = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryInode = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryMode = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryUid = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntryGid = dataBuffer.getInt();
            entryBytesRead += 4;
            int indexEntrySize = dataBuffer.getInt();
            entryBytesRead += 4;
            // if ( log.isDebugEnabled() ) log.debug("Entry "+ entryIndex + " has size "+
            // indexEntrySize);

            // size is unspecified for the entry id, but it seems to be a 40 hex character, SHA-1
            // string
            // stored as 20 bytes, network order
            byte[] indexEntryIdBuffer = new byte[20];
            dataBuffer.get(indexEntryIdBuffer);
            entryBytesRead += 20;
            String indexEntrySha1 = Hex.encodeHexString(indexEntryIdBuffer);

            short indexEntryFlags = dataBuffer.getShort();
            entryBytesRead += 2;
            // if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has flags " +
            // indexEntryFlags);

            // mask off all but the least significant 12 bits of the index entry flags to get the
            // length of the name in bytes
            int indexEntryNameByteLength = indexEntryFlags & 4095;
            // if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has a name of length
            // " + indexEntryNameByteLength);

            // mask off all but the second most significant 12 bit of the index entry flags to get
            // the extended flag for the entry
            int indexEntryExtendedFlag = ((indexEntryFlags & (1 << 14)) >> 14);
            // if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has an extended flag
            // of " + indexEntryExtendedFlag);

            // check that we parsed out the index entry extended flag correctly.
            // this is more of an assertion than anything. It's already saved my bacon once.
            if (indexEntryExtendedFlag != 0 && indexEntryExtendedFlag != 1) {
                throw new Exception(
                        "Error parsing out the extended flag for index entry "
                                + entryIndex
                                + ". We got "
                                + indexEntryExtendedFlag);
            }
            if (indexFileVersion == 2 && indexEntryExtendedFlag != 0) {
                throw new Exception(
                        "Index File Version 2 is supposed to have the extended flag set to 0. For index entry "
                                + entryIndex
                                + ", it is set to "
                                + indexEntryExtendedFlag);
            }

            // specific to version 3 and above, if the extended flag is set for the entry.
            if (indexFileVersion > 2 && indexEntryExtendedFlag == 1) {
                // if ( log.isDebugEnabled() ) log.debug ("For Index file version "+
                // indexFileVersion +", reading an extra 16 bits for Entry "+ entryIndex );
                short indexEntryExtendedFlags = dataBuffer.getShort();
                entryBytesRead += 2;
                // if ( log.isDebugEnabled() ) log.debug ("Entry "+ entryIndex + " has (optional)
                // extended flags " + indexEntryExtendedFlags);
            }

            String indexEntryName = null;
            if (indexFileVersion > 3) {
                // if ( log.isDebugEnabled() ) log.debug("Inflating the (deflated) entry name for
                // index entry "+ entryIndex + " based on the previous entry name, since Index file
                // version "+ indexFileVersion + " requires this");

                // get bytes until we find one with the msb NOT set. count the bytes.
                int n = 0, removeNfromPreviousName = 0;
                byte msbsetmask = (byte) (1 << 7); // 1000 0000
                byte msbunsetmask = (byte) ((~msbsetmask) & 0xFF); // 0111 1111
                while (++n > 0) {
                    byte byteRead = dataBuffer.get();
                    entryBytesRead++;
                    if (n == 1) // zero the msb of the first byte read
                    removeNfromPreviousName =
                                (removeNfromPreviousName << 8) | (0xFF & (byteRead & msbunsetmask));
                    else // set the msb of subsequent bytes read
                    removeNfromPreviousName =
                                (removeNfromPreviousName << 8) | (0xFF & (byteRead | msbsetmask));
                    if ((byteRead & msbsetmask) == 0) break; // break if msb is NOT set in the byte
                }

                // if (log.isDebugEnabled()) log.debug("We read "+ n + " bytes of variable length
                // data from before the start of the entry name");
                if (n > 4)
                    throw new Exception(
                            "An entry name is never expected to be > 2^^32 bytes long. Some file corruption may have occurred, or a parsing error has occurred");

                // now read the (partial) name for the current entry
                int bytesToReadCurrentNameEntry =
                        indexEntryNameByteLength
                                - (previousIndexEntryName.length() - removeNfromPreviousName);
                byte[] indexEntryNameBuffer = new byte[bytesToReadCurrentNameEntry];
                dataBuffer.get(indexEntryNameBuffer);
                entryBytesRead += bytesToReadCurrentNameEntry;

                // build it up
                indexEntryName =
                        previousIndexEntryName.substring(
                                        0,
                                        previousIndexEntryName.length() - removeNfromPreviousName)
                                + new String(indexEntryNameBuffer);
            } else {
                // indexFileVersion <= 3 (waaaaay simpler logic, but the index file is larger in
                // this version than for v4+)
                byte[] indexEntryNameBuffer = new byte[indexEntryNameByteLength];
                dataBuffer.get(indexEntryNameBuffer);
                entryBytesRead += indexEntryNameByteLength;
                indexEntryName = new String(indexEntryNameBuffer);
            }

            if (log.isDebugEnabled())
                log.debug("Entry " + entryIndex + " has name " + indexEntryName);

            // and store off the index entry name, for the next iteration
            previousIndexEntryName = indexEntryName;
            // skip past the zero byte terminating the string (whose purpose seems completely
            // pointless to me, but hey)
            byte indexEntryNul = dataBuffer.get();
            entryBytesRead++;

            // the padding after the pathname does not exist for versions 4 or later.
            if (indexFileVersion < 4) {
                // if ( log.isDebugEnabled() ) log.debug("Aligning to an 8 byte boundary after Entry
                // "+ entryIndex + ", since Index file version "+ indexFileVersion + " mandates 64
                // bit alignment for index entries");

                int entryBytesToRead = ((8 - (entryBytesRead % 8)) % 8);
                // if ( log.isDebugEnabled() ) {
                //	log.debug ("The number of bytes read for index entry "+ entryIndex + " thus far
                // is: "+ entryBytesRead);
                //	log.debug ("So we must read "+ entryBytesToRead + " bytes to stay on a 64 bit
                // boundary");
                // }

                // read the 0-7 (NUL) bytes to keep reading index entries on an 8 byte boundary
                byte[] indexEntryPadBuffer = new byte[entryBytesToRead];
                dataBuffer.get(indexEntryPadBuffer);
                entryBytesRead += entryBytesToRead;
            } else {
                // if ( log.isDebugEnabled() ) log.debug("Not aligning to an 8 byte boundary after
                // Entry "+ entryIndex + ", since Index file version "+ indexFileVersion + " does
                // not mandate 64 bit alignment for index entries");
            }

            // Git does not store entries for directories, but just files/symlinks/Git links, so no
            // need to handle directories here, unlike with SVN, for instance.
            if (indexEntryName != null && indexEntryName.length() > 0) {
                // log.info("Found file/symbolic link/gitlink "+ indexEntryName + " in the Git
                // entries file");
                map.put(indexEntryName, indexEntrySha1);
            }
        }
        return map;
    }

    /**
     * gets the base folder (ie, the ".git" folder), for the specified Git file
     *
     * @param gitFile a valid Git repository file, such as "/XYZ/.git/index"
     * @return the base folder (ie, the ".git" folder), for the specified Git file
     */
    public String getBaseFolder(String gitFile) {
        Matcher matcher = basefolderpattern.matcher(gitFile);
        if (matcher.matches()) return matcher.group(1);
        return null;
    }

    /**
     * validate a SHA1 for at least superficially valid from the point of view of Git
     *
     * @param sha1 the SHA1 value to validate
     * @return true if the SHA1 is at least superficially valid.
     */
    public boolean validateSHA1(String sha1) {
        if (sha1.length() != 40) return false; // 40 characters long
        if (!sha1pattern.matcher(sha1).find())
            return false; // where each character must be 0-9, or a-f.
        return true;
    }
}
