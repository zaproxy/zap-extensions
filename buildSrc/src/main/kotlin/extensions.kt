import com.diffplug.gradle.spotless.JavaExtension
import com.diffplug.gradle.spotless.SpotlessExtension
import org.gradle.api.Project

/**
 * Configures the java extension with all Java files except the given ones and configures
 * a format with Google Java Format (AOSP) for the given files.
 */
fun SpotlessExtension.javaWith3rdPartyFormatted(project: Project, files: List<String>) {
    java {
        target(project.fileTree(project.projectDir) {
            include("src/**/*.java")
            exclude(files)
        })
    }

    format("3rdParty", JavaExtension::class.java, {
        target(project.fileTree(project.projectDir) {
            include(files)
        })

        googleJavaFormatAosp()
    })
}

/**
 * Configures the Google Java Format (AOSP).
 */
fun JavaExtension.googleJavaFormatAosp(): Unit =
    googleJavaFormat("1.7").aosp()
