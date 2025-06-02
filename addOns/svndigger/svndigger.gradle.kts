import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.ProcessSvnDiggerFiles

description = "SVN Digger files which can be used with ZAP forced browsing"

val svndiggerDir = layout.buildDirectory.dir("zapAddOn/homeFiles/")
val processFiles by tasks.registering(ProcessSvnDiggerFiles::class) {
    outputDir.set(svndiggerDir)
}

zapAddOn {
    addOnName.set("SVN Digger Files")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/svn-digger-files/")
        files.from(svndiggerDir)

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

tasks.named(AddOnPlugin.GENERATE_MANIFEST_TASK_NAME) {
    dependsOn(processFiles)
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}

sourceSets["main"].output.dir(mapOf("builtBy" to processFiles), svndiggerDir)
