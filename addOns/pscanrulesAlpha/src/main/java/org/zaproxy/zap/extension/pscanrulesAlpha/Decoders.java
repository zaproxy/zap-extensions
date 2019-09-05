package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readNullTerminatedString;

public enum Decoders {
  NULL_TERMINATED_STRING(
      0x0B,
      bb -> {
        String nullterminatedString = readNullTerminatedString(bb);
        StringBuilder sb = new StringBuilder("<stringnullterminated>");
        sb.append(ViewStateByteReader.escapeString(nullterminatedString));
        sb.append("</stringnullterminated>");
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
      });

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
