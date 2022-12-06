import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides database engines and related infrastructure."

val datanucleus by configurations.creating
configurations.api { extendsFrom(datanucleus) }

val sqlite by configurations.creating
configurations.api { extendsFrom(sqlite) }

zapAddOn {
    addOnName.set("Database")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.12.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/database/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(datanucleus)
            libs.from(sqlite)
        }
    }
}

crowdin {
    configuration {
        file.set(file("$rootDir/gradle/crowdin-help-only.yml"))
        tokens.put("%helpPath%", "")
    }
}

spotless {
    format("help-html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(
            fileTree(projectDir) {
                include("src/**/help/**/*.html")
            }
        )
    })
}

dependencies {
    datanucleus("org.datanucleus:datanucleus-accessplatform-jdo-rdbms:6.0.1")
    sqlite("org.xerial:sqlite-jdbc:3.39.3.0")

    implementation("org.flywaydb:flyway-core:9.4.0")

    testImplementation(project(":testutils"))
}
