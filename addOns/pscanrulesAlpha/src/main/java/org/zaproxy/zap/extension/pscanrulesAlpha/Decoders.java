package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.ViewStateByteReader.readLittleEndianBase128Number;

public enum Decoders {
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
