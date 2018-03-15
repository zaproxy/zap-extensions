import org.parosproxy.paros.Constant
import org.zaproxy.zap.extension.script.ExtensionScript
import org.parosproxy.paros.network.HttpMessage

import java.nio.file.Paths

void invokeWith(HttpMessage msg){
    println("Start Debugging...")
    def relativeScriptFilePath = "scripts/targeted/TargetedDefaultTemplate.groovy"

    def scriptFilePath = Paths
            .get(Constant.getZapHome(), ExtensionScript.SCRIPTS_DIR, relativeScriptFilePath)
            .toAbsolutePath()
            .toString()

    def script = new File(scriptFilePath)
    def scriptFunc = evaluate(script)
    scriptFunc(msg)
    println("End Debugging...")
}

