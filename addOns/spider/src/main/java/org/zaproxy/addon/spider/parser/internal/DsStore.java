package org.zaproxy.addon.spider.parser.internal;

// https://formats.kaitai.io/ds_store/java.html
// Removed unnecessary int casts
// Added missing Override annotations
//This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import io.kaitai.struct.ByteBufferKaitaiStream;
import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.charset.Charset;


/**
* Apple macOS '.DS_Store' file format.
* @see <a href="https://en.wikipedia.org/wiki/.DS_Store
* https://metacpan.org/pod/distribution/Mac-Finder-DSStore/DSStoreFormat.pod
* https://0day.work/parsing-the-ds_store-file-format
* ">Source</a>
*/
public class DsStore extends KaitaiStruct {
 public static DsStore fromFile(String fileName) throws IOException {
     return new DsStore(new ByteBufferKaitaiStream(fileName));
 }

 public DsStore(KaitaiStream _io) {
     this(_io, null, null);
 }

 public DsStore(KaitaiStream _io, KaitaiStruct _parent) {
     this(_io, _parent, null);
 }

 public DsStore(KaitaiStream _io, KaitaiStruct _parent, DsStore _root) {
     super(_io);
     this._parent = _parent;
     this._root = _root == null ? this : _root;
     _read();
 }
 private void _read() {
     this.alignmentHeader = this._io.readBytes(4);
     if (!(Arrays.equals(alignmentHeader(), new byte[] { 0, 0, 0, 1 }))) {
         throw new KaitaiStream.ValidationNotEqualError(new byte[] { 0, 0, 0, 1 }, alignmentHeader(), _io(), "/seq/0");
     }
     this.buddyAllocatorHeader = new BuddyAllocatorHeader(this._io, this, _root);
 }
 public static class BuddyAllocatorHeader extends KaitaiStruct {
     public static BuddyAllocatorHeader fromFile(String fileName) throws IOException {
         return new BuddyAllocatorHeader(new ByteBufferKaitaiStream(fileName));
     }

     public BuddyAllocatorHeader(KaitaiStream _io) {
         this(_io, null, null);
     }

     public BuddyAllocatorHeader(KaitaiStream _io, DsStore _parent) {
         this(_io, _parent, null);
     }

     public BuddyAllocatorHeader(KaitaiStream _io, DsStore _parent, DsStore _root) {
         super(_io);
         this._parent = _parent;
         this._root = _root;
         _read();
     }
     private void _read() {
         this.magic = this._io.readBytes(4);
         if (!(Arrays.equals(magic(), new byte[] { 66, 117, 100, 49 }))) {
             throw new KaitaiStream.ValidationNotEqualError(new byte[] { 66, 117, 100, 49 }, magic(), _io(), "/types/buddy_allocator_header/seq/0");
         }
         this.ofsBookkeepingInfoBlock = this._io.readU4be();
         this.lenBookkeepingInfoBlock = this._io.readU4be();
         this.copyOfsBookkeepingInfoBlock = this._io.readU4be();
         this._unnamed4 = this._io.readBytes(16);
     }
     private byte[] magic;
     private long ofsBookkeepingInfoBlock;
     private long lenBookkeepingInfoBlock;
     private long copyOfsBookkeepingInfoBlock;
     private byte[] _unnamed4;
     private DsStore _root;
     private DsStore _parent;

     /**
      * Magic number 'Bud1'.
      */
     public byte[] magic() { return magic; }
     public long ofsBookkeepingInfoBlock() { return ofsBookkeepingInfoBlock; }
     public long lenBookkeepingInfoBlock() { return lenBookkeepingInfoBlock; }

     /**
      * Needs to match 'offset_bookkeeping_info_block'.
      */
     public long copyOfsBookkeepingInfoBlock() { return copyOfsBookkeepingInfoBlock; }

     /**
      * Unused field which might simply be the unused space at the end of the block,
      * since the minimum allocation size is 32 bytes.
      */
     public byte[] _unnamed4() { return _unnamed4; }
     public DsStore _root() { return _root; }
     @Override
     public DsStore _parent() { return _parent; }
 }
 public static class BuddyAllocatorBody extends KaitaiStruct {
     public static BuddyAllocatorBody fromFile(String fileName) throws IOException {
         return new BuddyAllocatorBody(new ByteBufferKaitaiStream(fileName));
     }

     public BuddyAllocatorBody(KaitaiStream _io) {
         this(_io, null, null);
     }

     public BuddyAllocatorBody(KaitaiStream _io, DsStore _parent) {
         this(_io, _parent, null);
     }

     public BuddyAllocatorBody(KaitaiStream _io, DsStore _parent, DsStore _root) {
         super(_io);
         this._parent = _parent;
         this._root = _root;
         _read();
     }
     private void _read() {
         this.numBlocks = this._io.readU4be();
         this._unnamed1 = this._io.readBytes(4);
         this.blockAddresses = new ArrayList<BlockDescriptor>();
         for (int i = 0; i < numBlockAddresses(); i++) {
             this.blockAddresses.add(new BlockDescriptor(this._io, this, _root));
         }
         this.numDirectories = this._io.readU4be();
         this.directoryEntries = new ArrayList<DirectoryEntry>();
         for (int i = 0; i < numDirectories(); i++) {
             this.directoryEntries.add(new DirectoryEntry(this._io, this, _root));
         }
         this.freeLists = new ArrayList<FreeList>();
         for (int i = 0; i < numFreeLists(); i++) {
             this.freeLists.add(new FreeList(this._io, this, _root));
         }
     }
     public static class BlockDescriptor extends KaitaiStruct {
         public static BlockDescriptor fromFile(String fileName) throws IOException {
             return new BlockDescriptor(new ByteBufferKaitaiStream(fileName));
         }

         public BlockDescriptor(KaitaiStream _io) {
             this(_io, null, null);
         }

         public BlockDescriptor(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent) {
             this(_io, _parent, null);
         }

         public BlockDescriptor(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent, DsStore _root) {
             super(_io);
             this._parent = _parent;
             this._root = _root;
             _read();
         }
         private void _read() {
             this.addressRaw = this._io.readU4be();
         }
         private Integer offset;
         public Integer offset() {
             if (this.offset != null)
                 return this.offset;
             int _tmp = (int) (((addressRaw() & ~(_root().blockAddressMask())) + 4));
             this.offset = _tmp;
             return this.offset;
         }
         private Integer size;
         public Integer size() {
             if (this.size != null)
                 return this.size;
             int _tmp = ((1 << (addressRaw() & _root().blockAddressMask())));
             this.size = _tmp;
             return this.size;
         }
         private long addressRaw;
         private DsStore _root;
         private DsStore.BuddyAllocatorBody _parent;
         public long addressRaw() { return addressRaw; }
         public DsStore _root() { return _root; }
         @Override
         public DsStore.BuddyAllocatorBody _parent() { return _parent; }
     }
     public static class DirectoryEntry extends KaitaiStruct {
         public static DirectoryEntry fromFile(String fileName) throws IOException {
             return new DirectoryEntry(new ByteBufferKaitaiStream(fileName));
         }

         public DirectoryEntry(KaitaiStream _io) {
             this(_io, null, null);
         }

         public DirectoryEntry(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent) {
             this(_io, _parent, null);
         }

         public DirectoryEntry(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent, DsStore _root) {
             super(_io);
             this._parent = _parent;
             this._root = _root;
             _read();
         }
         private void _read() {
             this.lenName = this._io.readU1();
             this.name = new String(this._io.readBytes(lenName()), Charset.forName("UTF-8"));
             this.blockId = this._io.readU4be();
         }
         private int lenName;
         private String name;
         private long blockId;
         private DsStore _root;
         private DsStore.BuddyAllocatorBody _parent;
         public int lenName() { return lenName; }
         public String name() { return name; }
         public long blockId() { return blockId; }
         public DsStore _root() { return _root; }
         @Override
         public DsStore.BuddyAllocatorBody _parent() { return _parent; }
     }
     public static class FreeList extends KaitaiStruct {
         public static FreeList fromFile(String fileName) throws IOException {
             return new FreeList(new ByteBufferKaitaiStream(fileName));
         }

         public FreeList(KaitaiStream _io) {
             this(_io, null, null);
         }

         public FreeList(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent) {
             this(_io, _parent, null);
         }

         public FreeList(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent, DsStore _root) {
             super(_io);
             this._parent = _parent;
             this._root = _root;
             _read();
         }
         private void _read() {
             this.counter = this._io.readU4be();
             this.offsets = new ArrayList<Long>();
             for (int i = 0; i < counter(); i++) {
                 this.offsets.add(this._io.readU4be());
             }
         }
         private long counter;
         private ArrayList<Long> offsets;
         private DsStore _root;
         private DsStore.BuddyAllocatorBody _parent;
         public long counter() { return counter; }
         public ArrayList<Long> offsets() { return offsets; }
         public DsStore _root() { return _root; }
         @Override
         public DsStore.BuddyAllocatorBody _parent() { return _parent; }
     }
     private Integer numBlockAddresses;
     public Integer numBlockAddresses() {
         if (this.numBlockAddresses != null)
             return this.numBlockAddresses;
         int _tmp = (256);
         this.numBlockAddresses = _tmp;
         return this.numBlockAddresses;
     }
     private Byte numFreeLists;
     public Byte numFreeLists() {
         if (this.numFreeLists != null)
             return this.numFreeLists;
         byte _tmp = (byte) (32);
         this.numFreeLists = _tmp;
         return this.numFreeLists;
     }
     private ArrayList<MasterBlockRef> directories;

     /**
      * Master blocks of the different B-trees.
      */
     public ArrayList<MasterBlockRef> directories() {
         if (this.directories != null)
             return this.directories;
         KaitaiStream io = _root()._io();
         this.directories = new ArrayList<MasterBlockRef>();
         for (int i = 0; i < numDirectories(); i++) {
             this.directories.add(new MasterBlockRef(io, this, _root, i));
         }
         return this.directories;
     }
     private long numBlocks;
     private byte[] _unnamed1;
     private ArrayList<BlockDescriptor> blockAddresses;
     private long numDirectories;
     private ArrayList<DirectoryEntry> directoryEntries;
     private ArrayList<FreeList> freeLists;
     private DsStore _root;
     private DsStore _parent;

     /**
      * Number of blocks in the allocated-blocks list.
      */
     public long numBlocks() { return numBlocks; }

     /**
      * Unknown field which appears to always be 0.
      */
     public byte[] _unnamed1() { return _unnamed1; }

     /**
      * Addresses of the different blocks.
      */
     public ArrayList<BlockDescriptor> blockAddresses() { return blockAddresses; }

     /**
      * Indicates the number of directory entries.
      */
     public long numDirectories() { return numDirectories; }

     /**
      * Each directory is an independent B-tree.
      */
     public ArrayList<DirectoryEntry> directoryEntries() { return directoryEntries; }
     public ArrayList<FreeList> freeLists() { return freeLists; }
     public DsStore _root() { return _root; }
     @Override
     public DsStore _parent() { return _parent; }
 }
 public static class MasterBlockRef extends KaitaiStruct {

     public MasterBlockRef(KaitaiStream _io, long idx) {
         this(_io, null, null, idx);
     }

     public MasterBlockRef(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent, long idx) {
         this(_io, _parent, null, idx);
     }

     public MasterBlockRef(KaitaiStream _io, DsStore.BuddyAllocatorBody _parent, DsStore _root, long idx) {
         super(_io);
         this._parent = _parent;
         this._root = _root;
         this.idx = idx;
         _read();
     }
     private void _read() {
     }
     public static class MasterBlock extends KaitaiStruct {
         public static MasterBlock fromFile(String fileName) throws IOException {
             return new MasterBlock(new ByteBufferKaitaiStream(fileName));
         }

         public MasterBlock(KaitaiStream _io) {
             this(_io, null, null);
         }

         public MasterBlock(KaitaiStream _io, DsStore.MasterBlockRef _parent) {
             this(_io, _parent, null);
         }

         public MasterBlock(KaitaiStream _io, DsStore.MasterBlockRef _parent, DsStore _root) {
             super(_io);
             this._parent = _parent;
             this._root = _root;
             _read();
         }
         private void _read() {
             this.blockId = this._io.readU4be();
             this.numInternalNodes = this._io.readU4be();
             this.numRecords = this._io.readU4be();
             this.numNodes = this._io.readU4be();
             this._unnamed4 = this._io.readU4be();
         }
         private Block rootBlock;
         public Block rootBlock() {
             if (this.rootBlock != null)
                 return this.rootBlock;
             KaitaiStream io = _root()._io();
             long _pos = io.pos();
             io.seek(_root().buddyAllocatorBody().blockAddresses().get((int) blockId()).offset());
             this.rootBlock = new Block(io, this, _root);
             io.seek(_pos);
             return this.rootBlock;
         }
         private long blockId;
         private long numInternalNodes;
         private long numRecords;
         private long numNodes;
         private long _unnamed4;
         private DsStore _root;
         private DsStore.MasterBlockRef _parent;

         /**
          * Block number of the B-tree's root node.
          */
         public long blockId() { return blockId; }

         /**
          * Number of internal node levels.
          */
         public long numInternalNodes() { return numInternalNodes; }

         /**
          * Number of records in the tree.
          */
         public long numRecords() { return numRecords; }

         /**
          * Number of nodes in the tree.
          */
         public long numNodes() { return numNodes; }

         /**
          * Always 0x1000, probably the B-tree node page size.
          */
         public long _unnamed4() { return _unnamed4; }
         public DsStore _root() { return _root; }
         @Override
         public DsStore.MasterBlockRef _parent() { return _parent; }
     }
     private MasterBlock masterBlock;
     public MasterBlock masterBlock() {
         if (this.masterBlock != null)
             return this.masterBlock;
         long _pos = this._io.pos();
         this._io.seek(_parent().blockAddresses().get((int) _parent().directoryEntries().get((int) idx()).blockId()).offset());
         this._raw_masterBlock = this._io.readBytes(_parent().blockAddresses().get((int) _parent().directoryEntries().get((int) idx()).blockId()).size());
         KaitaiStream _io__raw_masterBlock = new ByteBufferKaitaiStream(_raw_masterBlock);
         this.masterBlock = new MasterBlock(_io__raw_masterBlock, this, _root);
         this._io.seek(_pos);
         return this.masterBlock;
     }
     private long idx;
     private DsStore _root;
     private DsStore.BuddyAllocatorBody _parent;
     private byte[] _raw_masterBlock;
     public long idx() { return idx; }
     public DsStore _root() { return _root; }
     @Override
     public DsStore.BuddyAllocatorBody _parent() { return _parent; }
     public byte[] _raw_masterBlock() { return _raw_masterBlock; }
 }
 public static class Block extends KaitaiStruct {
     public static Block fromFile(String fileName) throws IOException {
         return new Block(new ByteBufferKaitaiStream(fileName));
     }

     public Block(KaitaiStream _io) {
         this(_io, null, null);
     }

     public Block(KaitaiStream _io, KaitaiStruct _parent) {
         this(_io, _parent, null);
     }

     public Block(KaitaiStream _io, KaitaiStruct _parent, DsStore _root) {
         super(_io);
         this._parent = _parent;
         this._root = _root;
         _read();
     }
     private void _read() {
         this.mode = this._io.readU4be();
         this.counter = this._io.readU4be();
         this.data = new ArrayList<BlockData>();
         for (int i = 0; i < counter(); i++) {
             this.data.add(new BlockData(this._io, this, _root, mode()));
         }
     }
     public static class BlockData extends KaitaiStruct {

         public BlockData(KaitaiStream _io, long mode) {
             this(_io, null, null, mode);
         }

         public BlockData(KaitaiStream _io, DsStore.Block _parent, long mode) {
             this(_io, _parent, null, mode);
         }

         public BlockData(KaitaiStream _io, DsStore.Block _parent, DsStore _root, long mode) {
             super(_io);
             this._parent = _parent;
             this._root = _root;
             this.mode = mode;
             _read();
         }
         private void _read() {
             if (mode() > 0) {
                 this.blockId = this._io.readU4be();
             }
             this.record = new Record(this._io, this, _root);
         }
         public static class Record extends KaitaiStruct {
             public static Record fromFile(String fileName) throws IOException {
                 return new Record(new ByteBufferKaitaiStream(fileName));
             }

             public Record(KaitaiStream _io) {
                 this(_io, null, null);
             }

             public Record(KaitaiStream _io, DsStore.Block.BlockData _parent) {
                 this(_io, _parent, null);
             }

             public Record(KaitaiStream _io, DsStore.Block.BlockData _parent, DsStore _root) {
                 super(_io);
                 this._parent = _parent;
                 this._root = _root;
                 _read();
             }
             private void _read() {
                 this.filename = new Ustr(this._io, this, _root);
                 this.structureType = new FourCharCode(this._io, this, _root);
                 this.dataType = new String(this._io.readBytes(4), Charset.forName("UTF-8"));
                 switch (dataType()) {
                 case "long": {
                     this.value = (Object) (this._io.readU4be());
                     break;
                 }
                 case "shor": {
                     this.value = (Object) (this._io.readU4be());
                     break;
                 }
                 case "comp": {
                     this.value = (Object) (this._io.readU8be());
                     break;
                 }
                 case "bool": {
                     this.value = (Object) (this._io.readU1());
                     break;
                 }
                 case "ustr": {
                     this.value = new Ustr(this._io, this, _root);
                     break;
                 }
                 case "dutc": {
                     this.value = (Object) (this._io.readU8be());
                     break;
                 }
                 case "type": {
                     this.value = new FourCharCode(this._io, this, _root);
                     break;
                 }
                 case "blob": {
                     this.value = new RecordBlob(this._io, this, _root);
                     break;
                 }
                 }
             }
             public static class RecordBlob extends KaitaiStruct {
                 public static RecordBlob fromFile(String fileName) throws IOException {
                     return new RecordBlob(new ByteBufferKaitaiStream(fileName));
                 }

                 public RecordBlob(KaitaiStream _io) {
                     this(_io, null, null);
                 }

                 public RecordBlob(KaitaiStream _io, DsStore.Block.BlockData.Record _parent) {
                     this(_io, _parent, null);
                 }

                 public RecordBlob(KaitaiStream _io, DsStore.Block.BlockData.Record _parent, DsStore _root) {
                     super(_io);
                     this._parent = _parent;
                     this._root = _root;
                     _read();
                 }
                 private void _read() {
                     this.length = this._io.readU4be();
                     this.value = this._io.readBytes(length());
                 }
                 private long length;
                 private byte[] value;
                 private DsStore _root;
                 private DsStore.Block.BlockData.Record _parent;
                 public long length() { return length; }
                 public byte[] value() { return value; }
                 public DsStore _root() { return _root; }
                 @Override
                 public DsStore.Block.BlockData.Record _parent() { return _parent; }
             }
             public static class Ustr extends KaitaiStruct {
                 public static Ustr fromFile(String fileName) throws IOException {
                     return new Ustr(new ByteBufferKaitaiStream(fileName));
                 }

                 public Ustr(KaitaiStream _io) {
                     this(_io, null, null);
                 }

                 public Ustr(KaitaiStream _io, DsStore.Block.BlockData.Record _parent) {
                     this(_io, _parent, null);
                 }

                 public Ustr(KaitaiStream _io, DsStore.Block.BlockData.Record _parent, DsStore _root) {
                     super(_io);
                     this._parent = _parent;
                     this._root = _root;
                     _read();
                 }
                 private void _read() {
                     this.length = this._io.readU4be();
                     this.value = new String(this._io.readBytes((2 * length())), Charset.forName("UTF-16BE"));
                 }
                 private long length;
                 private String value;
                 private DsStore _root;
                 private DsStore.Block.BlockData.Record _parent;
                 public long length() { return length; }
                 public String value() { return value; }
                 public DsStore _root() { return _root; }
                 @Override
                 public DsStore.Block.BlockData.Record _parent() { return _parent; }
             }
             public static class FourCharCode extends KaitaiStruct {
                 public static FourCharCode fromFile(String fileName) throws IOException {
                     return new FourCharCode(new ByteBufferKaitaiStream(fileName));
                 }

                 public FourCharCode(KaitaiStream _io) {
                     this(_io, null, null);
                 }

                 public FourCharCode(KaitaiStream _io, DsStore.Block.BlockData.Record _parent) {
                     this(_io, _parent, null);
                 }

                 public FourCharCode(KaitaiStream _io, DsStore.Block.BlockData.Record _parent, DsStore _root) {
                     super(_io);
                     this._parent = _parent;
                     this._root = _root;
                     _read();
                 }
                 private void _read() {
                     this.value = new String(this._io.readBytes(4), Charset.forName("UTF-8"));
                 }
                 private String value;
                 private DsStore _root;
                 private DsStore.Block.BlockData.Record _parent;
                 public String value() { return value; }
                 public DsStore _root() { return _root; }
                 @Override
                 public DsStore.Block.BlockData.Record _parent() { return _parent; }
             }
             private Ustr filename;
             private FourCharCode structureType;
             private String dataType;
             private Object value;
             private DsStore _root;
             private DsStore.Block.BlockData _parent;
             public Ustr filename() { return filename; }

             /**
              * Description of the entry's property.
              */
             public FourCharCode structureType() { return structureType; }

             /**
              * Data type of the value.
              */
             public String dataType() { return dataType; }
             public Object value() { return value; }
             public DsStore _root() { return _root; }
@Override
public DsStore.Block.BlockData _parent() { return _parent; }
         }
         private Block block;
         public Block block() {
             if (this.block != null)
                 return this.block;
             if (mode() > 0) {
                 KaitaiStream io = _root()._io();
                 long _pos = io.pos();
                 io.seek(_root().buddyAllocatorBody().blockAddresses().get((int) ((long) (blockId()))).offset());
                 this.block = new Block(io, this, _root);
                 io.seek(_pos);
             }
             return this.block;
         }
         private Long blockId;
         private Record record;
         private long mode;
         private DsStore _root;
         private DsStore.Block _parent;
         public Long blockId() { return blockId; }
         public Record record() { return record; }
         public long mode() { return mode; }
         public DsStore _root() { return _root; }
         @Override
         public DsStore.Block _parent() { return _parent; }
     }
     private Block rightmostBlock;

     /**
      * Rightmost child block pointer.
      */
     public Block rightmostBlock() {
         if (this.rightmostBlock != null)
             return this.rightmostBlock;
         if (mode() > 0) {
             KaitaiStream io = _root()._io();
             long _pos = io.pos();
             io.seek(_root().buddyAllocatorBody().blockAddresses().get((int) mode()).offset());
             this.rightmostBlock = new Block(io, this, _root);
             io.seek(_pos);
         }
         return this.rightmostBlock;
     }
     private long mode;
     private long counter;
     private ArrayList<BlockData> data;
     private DsStore _root;
     private KaitaiStruct _parent;

     /**
      * If mode is 0, this is a leaf node, otherwise it is an internal node.
      */
     public long mode() { return mode; }

     /**
      * Number of records or number of block id + record pairs.
      */
     public long counter() { return counter; }
     public ArrayList<BlockData> data() { return data; }
     public DsStore _root() { return _root; }
     @Override
     public KaitaiStruct _parent() { return _parent; }
 }
 private BuddyAllocatorBody buddyAllocatorBody;
 public BuddyAllocatorBody buddyAllocatorBody() {
     if (this.buddyAllocatorBody != null)
         return this.buddyAllocatorBody;
     long _pos = this._io.pos();
     this._io.seek((buddyAllocatorHeader().ofsBookkeepingInfoBlock() + 4));
     this._raw_buddyAllocatorBody = this._io.readBytes(buddyAllocatorHeader().lenBookkeepingInfoBlock());
     KaitaiStream _io__raw_buddyAllocatorBody = new ByteBufferKaitaiStream(_raw_buddyAllocatorBody);
     this.buddyAllocatorBody = new BuddyAllocatorBody(_io__raw_buddyAllocatorBody, this, _root);
     this._io.seek(_pos);
     return this.buddyAllocatorBody;
 }
 private Byte blockAddressMask;

 /**
  * Bitmask used to calculate the position and the size of each block
  * of the B-tree from the block addresses.
  */
 public Byte blockAddressMask() {
     if (this.blockAddressMask != null)
         return this.blockAddressMask;
     byte _tmp = (byte) (31);
     this.blockAddressMask = _tmp;
     return this.blockAddressMask;
 }
 private byte[] alignmentHeader;
 private BuddyAllocatorHeader buddyAllocatorHeader;
 private DsStore _root;
 private KaitaiStruct _parent;
 private byte[] _raw_buddyAllocatorBody;
 public byte[] alignmentHeader() { return alignmentHeader; }
 public BuddyAllocatorHeader buddyAllocatorHeader() { return buddyAllocatorHeader; }
 public DsStore _root() { return _root; }
@Override
 public KaitaiStruct _parent() { return _parent; }
 public byte[] _raw_buddyAllocatorBody() { return _raw_buddyAllocatorBody; }
}