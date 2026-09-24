// Deliberately insecure source fixture, never compiled or executed.
import java.io.ObjectInputStream;
import java.security.MessageDigest;
class App {
  void inspect(String user, java.sql.Statement stmt, ObjectInputStream stream) throws Exception {
    Runtime.getRuntime().exec(user);
    new ProcessBuilder(user);
    String query = "SELECT * FROM users WHERE name = " + user;
    stmt.executeQuery(query);
    stream.readObject();
    MessageDigest.getInstance("MD5");
  }
}
