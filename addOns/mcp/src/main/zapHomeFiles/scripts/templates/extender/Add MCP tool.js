// Adds an example MCP tool that echoes a message.
//
// Extender scripts allow you to add completely new functionality to ZAP.
// The install function is called when the script is enabled and the uninstall
// function when it is disabled. Any functionality added in the install function
// should be removed in the uninstall method.
//
// This script demonstrates how to register a custom MCP tool with the ZAP MCP
// Server. The MCP add-on must be installed for this to work.

var Control = Java.type("org.parosproxy.paros.control.Control");
var ExtensionMcp = Java.type("org.zaproxy.addon.mcp.ExtensionMcp");
var McpTool = Java.type("org.zaproxy.addon.mcp.McpTool");
var McpToolResult = Java.type("org.zaproxy.addon.mcp.McpToolResult");
var McpToolException = Java.type("org.zaproxy.addon.mcp.McpToolException");

const NAME = "example-tool";

function newTool() {
  return new (Java.extend(McpTool)) {
    getName: function() {
      return NAME;
    },

    getDescription: function() {
      return "An example MCP tool that echoes a message. Use this as a template for custom tools.";
    },

    getInputSchema: function() {
      var schema = McpTool.OBJECT_MAPPER.createObjectNode();
      schema.put("type", "object");
      var properties = schema.putObject("properties");
      properties.putObject("message").put("type", "string").put("description", "The message to echo");
      schema.putArray("required").add("message");
      return schema;
    },

    execute: function(arguments) {
      if (!arguments || !arguments.has("message")) {
        throw new McpToolException("The message parameter is required");
      }
      var message = arguments.get("message").asText();
      return McpToolResult.success("Echo: " + message);
    }
  };
}

/**
 * This function is called when the script is enabled.
 *
 * @param helper - a helper class which provides the methods:
 *   getView() - returns a View object (null in daemon mode)
 *   getApi() - returns an API object for adding API calls
 */
function install(helper) {
  var extMcp = Control.getSingleton().getExtensionLoader().getExtension(ExtensionMcp);
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
  var extMcp = Control.getSingleton().getExtensionLoader().getExtension(ExtensionMcp);
  if (extMcp !== null) {
    extMcp.getToolRegistry().unregisterTool(NAME);
  }
}
