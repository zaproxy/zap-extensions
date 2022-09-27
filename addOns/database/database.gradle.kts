import com.diffplug.spotless.extra.wtp.EclipseWtpFormatterStep
import org.zaproxy.gradle.addon.AddOnStatus

description = "Provides database engines and related infrastructure."

val sqlite by configurations.creating
configurations.api { extendsFrom(sqlite) }

zapAddOn {
    addOnName.set("Database")
    addOnStatus.set(AddOnStatus.ALPHA)
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/database/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }

        bundledLibs {
            libs.from(sqlite)
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}

spotless {
    format("help-html", {
        eclipseWtp(EclipseWtpFormatterStep.HTML)
        target(fileTree(projectDir) {
            include("src/**/help/**/*.html")
        })
    })
}

dependencies {
    sqlite("org.xerial:sqlite-jdbc:3.39.3.0")

    testImplementation(project(":testutils"))
}
