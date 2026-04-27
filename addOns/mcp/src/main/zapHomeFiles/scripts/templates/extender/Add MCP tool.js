// Adds an example MCP tool that echoes a message.
//
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall
// function when it is disabled. Any functionality added in the install function
// should be removed in the uninstall method.
//
// This script demonstrates how to register a custom MCP tool with the ZAP MCP
// Server. The MCP add-on must be installed for this to work.

const ExtensionMcp = Java.type("org.zaproxy.addon.mcp.ExtensionMcp");
const McpTool = Java.type("org.zaproxy.addon.mcp.McpTool");
const McpToolResult = Java.type("org.zaproxy.addon.mcp.McpToolResult");
const McpToolException = Java.type("org.zaproxy.addon.mcp.McpToolException");
const InputSchema = Java.type("org.zaproxy.addon.mcp.McpTool$InputSchema");
const PropertyDef = Java.type(
  "org.zaproxy.addon.mcp.McpTool$InputSchema$PropertyDef",
);
const HashMap = Java.type("java.util.HashMap");
const ArrayList = Java.type("java.util.ArrayList");

const NAME = "example-tool";

function newTool() {
  return new (Java.extend(McpTool))({
    getName: function () {
      return NAME;
    },

    getDescription: function () {
      return "An example MCP tool that echoes a message. Use this as a template for custom tools.";
    },

    getInputSchema: function () {
      var properties = new HashMap();
      properties.put("message", PropertyDef.ofString("The message to echo"));
      var required = new ArrayList();
      required.add("message");
      return new InputSchema(properties, required);
    },

    execute: function (arguments) {
      var message = arguments.getString("message");
      if (message === null || message.trim() === "") {
        throw new McpToolException("The message parameter is required");
      }
      return McpToolResult.success("Echo: " + message);
    },
  });
}

/**
 * This function is called when the script is enabled.
 *
 * @param helper - a helper class which provides the methods:
 *   getView() - returns a View object (null in daemon mode)
 *   getApi() - returns an API object for adding API calls
 */
function install(helper) {
  var extMcp = control.getExtensionLoader().getExtension(ExtensionMcp);
  if (extMcp === null) {
    print("MCP add-on is not installed. Cannot register example tool.");
    return;
  }
  extMcp.getToolRegistry().registerTool(newTool());
}

/**
 * This function is called when the script is disabled.
 *
 * @param helper - a helper class which provides the methods:
 *   getView() - returns a View object (null in daemon mode)
 *   getApi() - returns an API object for adding API calls
 */
function uninstall(helper) {
  var extMcp = control.getExtensionLoader().getExtension(ExtensionMcp);
  if (extMcp !== null) {
    extMcp.getToolRegistry().unregisterTool(NAME);
  }
}
