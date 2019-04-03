package org.zaproxy.zap.extension.sse;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;

import org.apache.commons.lang.time.FastDateFormat;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;

/**
 * This object is passed around and contains all details about an event.
 */
public class ServerSentEvent implements Message {

	/*
	 * Field names have to be compared literally (case sensitive)
	 */
	public static final String FIELD_NAME_EVENT = "event";
	public static final String FIELD_NAME_DATA = "data";
	public static final String FIELD_NAME_ID = "id";
	public static final String FIELD_NAME_RETRY = "retry";
	
	/**
	 * Used to format {@link ServerSentEvent#timestamp} in user's locale.
	 */
	private static final FastDateFormat dateFormatter;

	/**
	 * Use the static initializer for setting up one date formatter for all
	 * instances.
	 */
	static {
		// milliseconds are added later (via usage
		// java.sql.Timestamp.getNanos())
		dateFormatter = FastDateFormat.getDateTimeInstance(
				SimpleDateFormat.SHORT, SimpleDateFormat.MEDIUM,
				Constant.getLocale());
	}

	/**
	 * Used for identification. Consecutive number.
	 */
	private Integer id;

	/**
	 * Used for identification. Each event belongs to one stream.
	 */
	private Integer streamId;

	/**
	 * Payload of this event.
	 */
	private StringBuilder data = new StringBuilder();

	/**
	 * Name of event. Can be an arbitrary string.
	 */
	private String eventType = "";

	/**
	 * This must initially be the empty string.
	 */
	private String lastEventId = "";

	/**
	 * In milliseconds. This must initially be a user-agent-defined value,
	 * probably in the region of a few seconds.
	 */
	private Integer reconnectionTime;

	/**
	 * Contains original event string as retrieved.
	 */
	private String rawEvent = "";

	/**
	 * Indicates when this event was received
	 */
	private Long timestamp;
	
	/**
	 * Readable representation of timestamp, created once when
	 * {@link #timestamp} is set.
	 */
	private String dateTime = "";
	
	/**
	 * Contains the number of bytes that belong to this event, not just the
	 * length of data.
	 */
	private Long rawEventLength;

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public Integer getStreamId() {
		return streamId;
	}

	public void setStreamId(Integer streamId) {
		this.streamId = streamId;
	}

	public String getEventType() {
		return eventType;
	}

	public void setEventType(String eventType) {
		this.eventType = eventType;
	}

	public String getData() {
		return data.toString();
	}

	public void setData(String data) {
		this.data = new StringBuilder(data);
	}

	/**
	 * Appends given value to data. Automatically adds a LineFeed afterwards.
	 * 
	 * @param value
	 */
	public void appendData(String value) {
		data.append(value);
		data.append("\n");
	}

	public void finishData() {
		int length = data.length();
		if (length == 0) {
			return;
		} else if (data.substring(length - 1).equals("\n")) {
			// has got a LineFeed at the end of the buffer => remove
			data.deleteCharAt(length - 1);
		}
		data.trimToSize();
	}

	public boolean isDataEmpty() {
		return (data.length() == 0);
	}

	public String getLastEventId() {
		return lastEventId;
	}

	public void setLastEventId(String lastEventId) {
		this.lastEventId = lastEventId;
	}

	public Integer getReconnectionTime() {
		return reconnectionTime;
	}

	public void setReconnectionTime(Integer reconnectionTime) {
		this.reconnectionTime = reconnectionTime;
	}

	public void setRawEvent(String rawEvent) {
		this.rawEvent = rawEvent;
	}

	public String getRawEvent() {
		return rawEvent;
	}

	@Override
	public String toString() {
		return "#" + this.streamId + "." + this.id;
	}

	public void setTime(Timestamp timestamp) {
		this.timestamp = timestamp.getTime();

		synchronized (dateFormatter) {
			dateTime = dateFormatter.format(timestamp);
		}
	}

	public void setTime(Long time) {
		this.timestamp = time;

		synchronized (dateFormatter) {
			dateTime = dateFormatter.format(time);
		}
	}

	public Long getTimestamp() {
		return timestamp;
	}

	@Override
	public boolean isInScope() {
		// TODO Auto-generated method stub
		return true;
	}

	public String getDateTime() {
		return dateTime;
	}

	public Long getRawEventLength() {
		if (rawEventLength == null) {
			// determine number of bytes
			rawEventLength = (long) getRawEvent().getBytes().length;
		}
		return rawEventLength;
	}
	
	public void setRawEventLength(Long length) {
		this.rawEventLength = length;
	}

	@Override
	public boolean isForceIntercept() {
		// Not currently supported for Server-Sent events.
		return false;
	}

	//@Override
	public String getHeader(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}
}
