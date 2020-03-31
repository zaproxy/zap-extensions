import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.ProcessSvnDiggerFiles

version = "4"
description = "SVN Digger files which can be used with ZAP forced browsing"

val svndiggerDir = file("$buildDir/zapAddOn/homeFiles/")
val processFiles by tasks.registering(ProcessSvnDiggerFiles::class) {
    outputDir.set(svndiggerDir)
}

zapAddOn {
    addOnName.set("SVN Digger Files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

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

sourceSets["main"].output.dir(mapOf("builtBy" to processFiles), svndiggerDir)
