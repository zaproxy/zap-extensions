package org.zaproxy.zap.extension.codedx;

import net.sf.json.JSONObject;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class CodeDxAPI extends ApiImplementor {

	private static final Logger LOGGER = LogManager.getLogger(CodeDxExtension.class);

	private static final String PREFIX = "codedx";

	private static final String VIEW_GENERATE = "generateReport";
	private static final String ACTION_UPLOAD = "uploadReport";
	private static final String ACTION_GEN_UPLOAD = "generateAndUpload";

	private static final String ACTION_PARAM_FILE_PATH = "filePath";
	private static final String ACTION_PARAM_SERVER_URL = "serverUrl";
	private static final String ACTION_PARAM_API_KEY = "codeDxApiKey";
	private static final String ACTION_PARAM_PROJECT = "projectId";

	// Optional
	private static final String ACTION_PARAM_FINGERPRINT = "fingerprint";
	private static final String ACTION_PARAM_ACCEPT_PERM = "acceptPermanently";

	private CodeDxExtension extension;

	public CodeDxAPI(CodeDxExtension extension) {
		this.extension = extension;
		this.addApiView(new ApiView(VIEW_GENERATE));

		String[] optionalParams = new String[] {
			ACTION_PARAM_FINGERPRINT,
			ACTION_PARAM_ACCEPT_PERM
		};

		this.addApiAction(
			new ApiAction(ACTION_UPLOAD,
				new String[] {
					ACTION_PARAM_FILE_PATH,
					ACTION_PARAM_SERVER_URL,
					ACTION_PARAM_API_KEY,
					ACTION_PARAM_PROJECT
				}, optionalParams
			)
		);
		this.addApiAction(
			new ApiAction(ACTION_GEN_UPLOAD,
				new String[] {
					ACTION_PARAM_SERVER_URL,
					ACTION_PARAM_API_KEY,
					ACTION_PARAM_PROJECT
				}, optionalParams
			)
		);
	}

	@Override
	public String getPrefix() {
        return PREFIX;
    }

	@Override
	public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
		if(ACTION_UPLOAD.equals(name)) {
			File reportFile = new File(params.getString(ACTION_PARAM_FILE_PATH));
			String serverUrl = params.getString(ACTION_PARAM_SERVER_URL);
			String apiKey = params.getString(ACTION_PARAM_API_KEY);
			String projectId = params.getString(ACTION_PARAM_PROJECT);

			String fingerprint = this.getParam(params, ACTION_PARAM_FINGERPRINT, "");
			boolean acceptPermanently = this.getParam(params, ACTION_PARAM_ACCEPT_PERM, false);

			uploadFile(reportFile, serverUrl, apiKey, projectId, fingerprint, acceptPermanently);
			return ApiResponseElement.OK;
		}
		else if(ACTION_GEN_UPLOAD.equals(name)) {
			File reportFile;
			String serverUrl = params.getString(ACTION_PARAM_SERVER_URL);
			String apiKey = params.getString(ACTION_PARAM_API_KEY);
			String projectId = params.getString(ACTION_PARAM_PROJECT);

			String fingerprint = this.getParam(params, ACTION_PARAM_FINGERPRINT, "");
			boolean acceptPermanently = this.getParam(params, ACTION_PARAM_ACCEPT_PERM, false);

			boolean isEmpty = false;
			try {
				reportFile = UploadActionListener.generateReportFile(extension);
				isEmpty = UploadActionListener.reportIsEmpty(reportFile);
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
				throw new ApiException(Type.INTERNAL_ERROR, e.getMessage());
			}
			try {
				if(!isEmpty)
					uploadFile(reportFile, serverUrl, apiKey, projectId, fingerprint, acceptPermanently);
				else
					return new ApiResponseElement("Result", "empty");
			} finally {
				reportFile.delete();
			}
			return ApiResponseElement.OK;
		}
		throw new ApiException(Type.BAD_ACTION);
	}

	@Override
	public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
		if(VIEW_GENERATE.equals(name)) {
			try {
				StringBuilder report = new StringBuilder();
				UploadActionListener.generateReportString(extension, report);
				return new ApiResponseElement(name, report.toString());
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
				throw new ApiException(Type.INTERNAL_ERROR, e.getMessage());
			}
		}
		throw new ApiException(Type.BAD_VIEW);
	}

	private void uploadFile(
		File reportFile,
		String serverUrl,
		String apiKey,
		String project,
		String fingerprint,
		boolean acceptPermanently
	) throws ApiException {
		if(serverUrl.endsWith("/"))
			serverUrl = serverUrl.substring(0, serverUrl.length()-1);
		try {
			CloseableHttpClient client = extension.getHttpClient(serverUrl, fingerprint, acceptPermanently);
			String err = UploadActionListener.uploadFile(client, reportFile, serverUrl, apiKey, project);
			if(err != null) {
				LOGGER.error(err);
				throw new ApiException(Type.ILLEGAL_PARAMETER, err);
			}
		} catch (GeneralSecurityException | IOException e) {
			LOGGER.error(e.getMessage(), e);
			throw new ApiException(Type.ILLEGAL_PARAMETER, e.getMessage());
		}
	}
}
