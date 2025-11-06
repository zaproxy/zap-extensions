package org.zaproxy.zap.extension.foxhound;

import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.foxhound.alerts.FoxhoundAlertHelper;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundOptions;
import org.zaproxy.zap.extension.foxhound.taint.TaintDeserializer;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfo;
import org.zaproxy.zap.extension.foxhound.taint.TaintInfoStore;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

public class FoxhoundExportServer extends PluginPassiveScanner {
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundExportServer.class);

    static Server server = null;
    private static int port = -1;

    private ExtensionNetwork extensionNetwork = null;
    private TaintInfoStore store = null;

    public FoxhoundExportServer() {

    }

    public void start(ExtensionNetwork network, FoxhoundOptions options, TaintInfoStore store) {
        LOGGER.info("start");
        this.extensionNetwork = network;
        this.store = store;
        port = options.getServerPort();
        getServer();
    }

    public void stop() {
        if (server != null) {
            try {
                server.stop();
            } catch (IOException e) {
                LOGGER.debug("An error occurred while stopping the proxy.", e);
            }
        }
    }

    private void analyseTaintFlow(String body) {
        TaintInfo taint = TaintDeserializer.deserializeTaintInfo(body);
        if (store != null) {
            store.addTaintInfo(taint);
        }
    }

    private Server getServer() {
        if (server == null) {
            server = extensionNetwork.createHttpServer(
                new HttpMessageHandler() {
                    @Override
                    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
                        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
                        try {
                            String body = msg.getRequestBody().toString();
                            analyseTaintFlow(body);

                            msg.getResponseHeader().setStatusCode(200);
                            msg.setResponseBody("OK");
                        } catch (Exception e) {
                            LOGGER.warn(e);
                            StringWriter sw = new StringWriter();
                            PrintWriter pw = new PrintWriter(sw);
                            e.printStackTrace(pw);
                            String sStackTrace = sw.toString(); // stack trace as a string
                            LOGGER.warn(sStackTrace);
                            msg.getResponseHeader().setStatusCode(500);
                            msg.setResponseBody("ERROR");
                        }
                    }
                });
            try {
                server.start(port);
                LOGGER.info("Starting Foxhound Export server on port:" + port);
            } catch (IOException e) {
                LOGGER.warn("An error occurred while starting the proxy.", e);
            }
        }
        return server;
    }


    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        LOGGER.debug("scanHttpResponseReceive() In Scan Http ResponseReceive," +
                " id=" + msg.getHistoryRef().getHistoryId() +
                " session=" + msg.getHistoryRef().getSessionId() +
                " url=" + msg.getRequestHeader().getURI());
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        LOGGER.debug("scanHttpRequestSend() In Scan Http ResponseReceive, " +
                "id=" + msg.getHistoryRef().getHistoryId() +
                " url=" + msg.getRequestHeader().getURI());
    }

    @Override
    public String getName() {
        return "Foxhound Taint Flow Scanner";
    }

    @Override
    public int getPluginId() {
        return 40099;
    }
}
