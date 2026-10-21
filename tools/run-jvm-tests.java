// SPDX-License-Identifier: Apache-2.0
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/**
 * Компилирует core/jvm и запускает CoreTests без javac в PATH и без Gradle:
 *   java tools/run-jvm-tests.java
 * Нужен JDK 17+ (модуль jdk.compiler).
 */
public class RunJvmTests {
    public static void main(String[] args) throws Exception {
        Path project = Path.of(System.getProperty("user.dir"));
        if (!Files.isDirectory(project.resolve("core/jvm"))) {
            project = Path.of(args.length > 0 ? args[0] : ".").toAbsolutePath();
        }
        Path out = Files.createTempDirectory("skhoron2fa-classes");
        List<String> sources;
        try (Stream<Path> walk = Files.walk(project.resolve("core/jvm"))) {
            sources = walk.filter(p -> p.toString().endsWith(".java")).map(Path::toString).collect(Collectors.toList());
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            System.err.println("Нет компилятора Java (нужен JDK, не JRE)");
            System.exit(2);
        }
        List<String> options = List.of("-d", out.toString(), "-Xlint:all", "-Werror");
        List<String> command = new java.util.ArrayList<>(options);
        command.addAll(sources);
        int rc = compiler.run(null, null, null, command.toArray(new String[0]));
        if (rc != 0) {
            System.err.println("Компиляция не удалась");
            System.exit(rc);
        }
        try (URLClassLoader loader = new URLClassLoader(new URL[]{out.toUri().toURL()})) {
            Class<?> tests = loader.loadClass("org.skhoron.twofa.core.CoreTests");
            Method main = tests.getMethod("main", String[].class);
            String outDir = System.getenv("SKHORON_JAVA_OUT");   // куда Java положит файл экспорта для проверки в Python
            String vectors = project.resolve("core/test-vectors").toString();
            String[] testArgs = outDir == null ? new String[]{vectors} : new String[]{vectors, outDir};
            main.invoke(null, (Object) testArgs);
        }
    }
}