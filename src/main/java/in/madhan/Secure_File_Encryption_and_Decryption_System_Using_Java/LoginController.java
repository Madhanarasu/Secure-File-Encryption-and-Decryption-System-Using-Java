package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.IOException;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class LoginController {

    @FXML
    private VBox loginPane;

    @FXML
    private TextField usernameField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label statusLabel;

    @FXML
    private void handleLogin() {
        String user = usernameField.getText().trim();
        String pass = passwordField.getText();

        if (user.isEmpty() || pass.isEmpty()) {
            statusLabel.setText("Please enter username and password");
            return;
        }

        if (DBController.validateUser(user, pass)) {
            loadMainUI(user);
        } else {
            statusLabel.setText("Invalid credentials");
        }
    }

    private void loadMainUI(String username) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/MainUI.fxml"));
            Parent root = loader.load();

            // Pass username to MainController to set permissions
            MainController controller = loader.getController();
            controller.initSession(username);

            Stage stage = (Stage) loginPane.getScene().getWindow();
            Scene scene = new Scene(root);
            stage.setScene(scene);
            stage.centerOnScreen();
        } catch (IOException e) {
            e.printStackTrace();
            statusLabel.setText("Error loading main UI: " + e.getMessage());
        }
    }
}
