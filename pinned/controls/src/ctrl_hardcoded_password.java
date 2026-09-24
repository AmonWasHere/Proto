package controls;

import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Hardcoded credential (CWE-798).
 *
 * The secret is in the source, so it is in every clone, fork, backup and build
 * artefact, and it cannot be rotated without a code change and a redeploy.
 */
public class ctrl_hardcoded_password {

    private static final String DB_PASSWORD = "s3cr3t-Pr0duction-Pa55w0rd";

    public Connection connect() throws Exception {
        return DriverManager.getConnection(
                "jdbc:mysql://db.internal/app", "admin", DB_PASSWORD);
    }
}
