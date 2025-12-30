import net.ltgt.gradle.errorprone.errorprone
import org.zaproxy.gradle.addon.AddOnStatus

description = "A common library, for use by other add-ons."

plugins {
    antlr
}

zapAddOn {
    addOnName.set("Common Library")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/common-library/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        file.set(file("$projectDir/gradle/crowdin.yml"))
        tokens.put("%helpPath%", "")
    }
}

dependencies {
    api(platform(libs.commonlib.jackson.bom))
    api(libs.commonlib.jackson.databind)
    api(libs.commonlib.jackson.dataformat.xml)
    api(libs.commonlib.jackson.dataformat.yaml)
    api(libs.commonlib.jackson.datatype.jdk8)
    api(libs.commonlib.jackson.datatype.jsr310)

    implementation(libs.commonlib.apache.commons.io)
    implementation(libs.commonlib.apache.commons.csv)
    implementation(libs.commonlib.apache.commons.collections4)

    val antlrVersion = "4.13.0"
    antlr("org.antlr:antlr4:$antlrVersion")
    implementation("org.antlr:antlr4-runtime:$antlrVersion")

    testImplementation(project(":testutils"))
}

val jsParserPkg = "org.zaproxy.addon.commonlib.parserapi.impl"
val jsParserDir = jsParserPkg.replace('.', '/')
val generateGrammarSource by tasks.existing(AntlrTask::class) {
    val libDir = "$outputDirectory/$jsParserDir"
    arguments = arguments + listOf("-package", jsParserPkg, "-lib", libDir)

    doFirst {
        mkdir(libDir)
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.errorprone.excludedPaths.set(".*/(generated-src|$jsParserDir)/.*")
}

tasks.named("generateGrammarSource") {
    mustRunAfter(tasks.named("generateEffectiveLombokConfig"))
}

spotless {
    javaWith3rdPartyFormatted(
        project,
        listOf("src/**/$jsParserDir/*.java"),
    )
}
