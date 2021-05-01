import groovy.transform.Field
import org.parosproxy.paros.Constant
import org.zaproxy.zap.extension.script.ExtensionScript
import org.parosproxy.paros.network.HttpMessage

import java.nio.file.Paths

@Field final def wrappedScript = debug()

def debug() {
    def relativeScriptFilePath = "scripts/targeted/TargetedDefaultTemplate.groovy"

    def scriptFilePath = Paths
            .get(Constant.getZapHome(), ExtensionScript.SCRIPTS_DIR, relativeScriptFilePath)
            .toAbsolutePath()
            .toString()

    def script = new File(scriptFilePath)
    def scriptFunctions = evaluate(script)
    return scriptFunctions
}

void invokeWith(HttpMessage msg){
    println("Start Debugging...")
    wrappedScript.invokeWith(msg)
    println("End Debugging...")
}

