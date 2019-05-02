import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.tasks.ProcessSvnDiggerFiles

version = "4"
description = "SVN Digger files which can be used with ZAP forced browsing"

val svndiggerDir = file("$buildDir/zapAddOn/homeFiles/")
val processFiles by tasks.registering(ProcessSvnDiggerFiles::class) {
    outputDir.set(svndiggerDir)
}

zapAddOn {
    addOnName.set("SVN Digger files")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.5.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("http://www.mavitunasecurity.com/blog/svn-digger-better-lists-for-forced-browsing/")
        files.from(svndiggerDir)
    }
}

sourceSets["main"].output.dir(mapOf("builtBy" to processFiles), svndiggerDir)
