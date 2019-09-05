package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.apache.commons.codec.binary.Hex;
import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.zaproxy.zap.extension.pscanrulesAlpha.ViewStateDecoder.decodeObjectAsXML;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readBytes;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readNullTerminatedString;

public enum Decoders {
  ARRAY_OF_STRING(
      0x15,
      bb -> {
        StringBuilder sb2 = new StringBuilder();
        int stringarraysize = readLittleEndianBase128Number(bb);
        sb2.append(String.format("<stringarray size=\"%d\">", stringarraysize));
        for (int j = 0; j < stringarraysize; j++) {
          int stringlength = bb.get();
          String string = new String(readBytes(bb, stringlength));
          sb2.append(String.format("<stringwithlength length=\"%d\">", stringlength));
          sb2.append(ViewStateByteReader.escapeString(string));
          sb2.append("</stringwithlength>");
        }
        sb2.append("</stringarray>");
        return Optional.of(sb2);
      }),
  CONTAINERS_OF_BOOLEANS(
      0x03,
      bb -> {
        StringBuilder sb = new StringBuilder();
        int booleancontainersize = readLittleEndianBase128Number(bb);
        sb.append(String.format("<booleanarray size=\"%d\">", booleancontainersize));
        for (int i = 0; i < booleancontainersize; i++) {
          try {
            sb.append(decodeObjectAsXML(bb));
          } catch (Exception e) {
            return Optional.empty();
          }
        }
        sb.append("</booleanarray>");
        return Optional.of(sb);
      }),
  CONTAINER_OF_OBJECTS(
      0x16,
      bb -> {
        int objectcontainersize = readLittleEndianBase128Number(bb);
        StringBuilder sb1 = new StringBuilder();
        sb1.append(String.format("<objectarray size=\"%d\">", objectcontainersize));
        for (int i = 0; i < objectcontainersize; i++) {
          try {
            sb1.append(decodeObjectAsXML(bb));
          } catch (Exception e) {
            return Optional.empty();
          }
        }
        sb1.append("</objectarray>");
        return Optional.of(sb1);
      }),
  CONTROL_STATE(
      0x18,
      bb -> {
        int controlstatelength = readLittleEndianBase128Number(bb);
        StringBuilder sb =
            new StringBuilder(String.format("<controlstate size=\"%d\">", controlstatelength));
        try {
          sb.append(decodeObjectAsXML(bb));
          sb.append(decodeObjectAsXML(bb));
        } catch (Exception e) {
          return Optional.empty();
        }
        sb.append("</controlstate>");
        return Optional.of(sb);
      }),
  EMPTY_NODE(0x64, bb -> Optional.of(new StringBuilder("<emptynode></emptynode>"))),
  EMPTY_STRING(0x65, bb -> Optional.of(new StringBuilder("<emptystring></emptystring>"))),
  FALSE(0x68, bb -> Optional.of(new StringBuilder("<boolean>false</boolean>"))),
  NULL_TERMINATED_STRING(
      0x0B,
      bb -> {
        String nullterminatedString = readNullTerminatedString(bb);
        StringBuilder sb = new StringBuilder("<stringnullterminated>");
        sb.append(ViewStateByteReader.escapeString(nullterminatedString));
        sb.append("</stringnullterminated>");
        return Optional.of(sb);
      }),
  STRING_REFERENCE(
      0x1F,
      bb -> {
        int stringref = readLittleEndianBase128Number(bb);
        StringBuilder sb = new StringBuilder("<stringreference>");
        sb.append(stringref);
        sb.append("</stringreference>");
        return Optional.of(sb);
      }),
  STRING(
      0x05,
      bb -> {
        int stringsize = readLittleEndianBase128Number(bb);
        String string = new String(readBytes(bb, stringsize));
        StringBuilder sb = new StringBuilder("<string>");
        sb.append(ViewStateByteReader.escapeString(string));
        sb.append("</string>");
        return Optional.of(sb);
      }),
  OTHER_STRING(0x1E, STRING.decoder),
  RGBA_COMPONENT(
      0x09,
      bb -> {
        byte[] rgbabytes = new byte[4];
        bb.get(rgbabytes);
        String rgbaashexstring = Hex.encodeHexString(rgbabytes);
        StringBuilder sb = new StringBuilder("<rgba>0x");
        sb.append(rgbaashexstring);
        sb.append("</rgba>");
        return Optional.of(sb);
      }),
  TRIPLE(0x10, bb ->{
      StringBuilder sb = new StringBuilder("<triple>");
      try {
          sb.append(decodeObjectAsXML(bb));
          sb.append(decodeObjectAsXML(bb));
          sb.append(decodeObjectAsXML(bb));
      } catch (Exception e) {
          return Optional.empty();
      }
      sb.append("</triple>");
      return Optional.of(sb);
  }),
  TRUE(0x67, bb -> Optional.of(new StringBuilder("<boolean>true</boolean>"))),
  TUPLE(0x0F, bb -> {
      StringBuilder sb = new StringBuilder("<pair>");
      try {
          sb.append(decodeObjectAsXML(bb));
          sb.append(decodeObjectAsXML(bb));
      } catch (Exception e) {
          return Optional.empty();
      }
      sb.append("</pair>");
      return Optional.of(sb);
  }),
  UNIT(
      0x1B,
      bb -> {
        byte[] unitbytes = new byte[12];
        bb.get(unitbytes);
        String unitashexstring = Hex.encodeHexString(unitbytes);
        StringBuilder sb = new StringBuilder("<unit>0x");
        sb.append(unitashexstring);
        sb.append("</unit>");
        return Optional.of(sb);
      }),
  UNSIGNED_INT(
      0x02,
      bb -> {
        int intSize = readLittleEndianBase128Number(bb);
        StringBuilder sb = new StringBuilder("<uint32>");
        sb.append(intSize);
        sb.append("</uint32>");
        return Optional.of(sb);
      }),
  UUID(
      0x24,
      bb -> {
        byte[] uuidbytes = new byte[36];
        bb.get(uuidbytes);
        String uuidashexstring = Hex.encodeHexString(uuidbytes);
        StringBuilder sb = new StringBuilder("<uuid>0x");
        sb.append(uuidashexstring);
        sb.append("</uuid>");
        return Optional.of(sb);
      }),
  ZERO(0x66, bb -> Optional.of(new StringBuilder("<zero></zero>")));

  final int type;
  final Function<ByteBuffer, Optional<StringBuilder>> decoder;

  Decoders(int type, Function<ByteBuffer, Optional<StringBuilder>> decoder) {
    this.type = type;
    this.decoder = decoder;
  }

  private static final Map<Integer, Decoders> BY_TYPE = new HashMap<>();

  static {
    for (Decoders e : values()) {
      BY_TYPE.put(e.type, e);
    }
  }

  public static Optional<Decoders> findBy(int type) {
    return Optional.ofNullable(BY_TYPE.get(type));
  }
}
