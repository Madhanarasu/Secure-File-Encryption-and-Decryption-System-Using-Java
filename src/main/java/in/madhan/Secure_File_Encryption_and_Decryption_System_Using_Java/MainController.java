package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.RadioButton;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {

    @FXML
    private TextField inputFileField;
    @FXML
    private TextField outputFileField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private PasswordField confirmPasswordField;
    @FXML
    private Button encryptButton;
    @FXML
    private Button decryptButton;
    @FXML
    private Button browseButton;
    @FXML
    private Button selectButton;
    @FXML
    private Button generateButton;
    @FXML
    private CheckBox showKeyCheck;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private Label statusText;
    @FXML
    private ToggleGroup modeGroup;
    @FXML
    private Label currentUserLabel;
    @FXML
    private ListView<String> logsListView;

    // Admin Controls
    @FXML
    private TabPane mainTabPane;
    @FXML
    private Tab adminTab;
    @FXML
    private TextField regUsernameField;
    @FXML
    private PasswordField regPasswordField;
    @FXML
    private PasswordField regConfirmPasswordField;
    @FXML
    private Label regStatusLabel;

    private String currentUser;

    public void initSession(String username) {
        this.currentUser = username;
        if (currentUserLabel != null) {
            currentUserLabel.setText(username);
        }

        // Admin Logic: Show/Hide Admin Tab
        if (adminTab != null && mainTabPane != null) {
            if ("admin".equals(username)) {
                if (!mainTabPane.getTabs().contains(adminTab)) {
                    mainTabPane.getTabs().add(adminTab);
                }
            } else {
                mainTabPane.getTabs().remove(adminTab);
            }
        }

        loadLogs();
    }

    @FXML
    private void initialize() {
        if (progressBar != null)
            progressBar.setProgress(0);
        if (statusText != null)
            statusText.setText("Ready");
        // Hide admin tab by default until initialized
        if (mainTabPane != null && adminTab != null) {
            mainTabPane.getTabs().remove(adminTab);
        }
    }

    @FXML
    private void onBrowse() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Input File");
        File f = chooser.showOpenDialog(browseButton.getScene().getWindow());
        if (f != null)
            inputFileField.setText(f.getAbsolutePath());
    }

    @FXML
    private void onSelectOutput() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select Output File");
        File f = chooser.showSaveDialog(selectButton.getScene().getWindow());
        if (f != null)
            outputFileField.setText(f.getAbsolutePath());
    }

    @FXML
    private void onEncrypt() {
        process(true);
    }

    @FXML
    private void onDecrypt() {
        process(false);
    }

    private void process(boolean encrypt) {
        String in = inputFileField.getText();
        String out = outputFileField.getText();
        String pwd = passwordField.getText();
        String conf = confirmPasswordField.getText();

        if (in == null || in.isBlank()) {
            setStatus("Select an input file");
            return;
        }
        if (out == null || out.isBlank()) {
            setStatus("Select an output file");
            return;
        }
        if (pwd == null || pwd.isEmpty()) {
            setStatus("Enter a password");
            return;
        }
        if (encrypt && !pwd.equals(conf)) {
            setStatus("Passwords do not match");
            return;
        }

        Path inPath = Paths.get(in);
        Path outPath = Paths.get(out);
        char[] password = pwd.toCharArray();

        String action = encrypt ? "Encrypting" : "Decrypting";
        setStatus(action + "...");
        progressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        disableButtons(true);

        CompletableFuture.runAsync(() -> {
            try {
                if (encrypt) {
                    if (CryptoService.isEncryptedFile(inPath)) {
                        Platform.runLater(() -> {
                            javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                                    javafx.scene.control.Alert.AlertType.CONFIRMATION);
                            alert.setTitle("Double Encryption Warning");
                            alert.setHeaderText("The input file appears to be already encrypted.");
                            alert.setContentText(
                                    "Encrypting it again means you will need to decrypt it twice to recover the original file.\n\nDo you want to proceed?");
                            alert.showAndWait().ifPresent(res -> {
                                if (res == javafx.scene.control.ButtonType.OK) {
                                    startCrypto(inPath, outPath, password, true);
                                } else {
                                    Platform.runLater(() -> setStatus("Encryption cancelled."));
                                    disableButtons(false);
                                }
                            });
                        });
                    } else {
                        startCrypto(inPath, outPath, password, true);
                    }
                } else {
                    startCrypto(inPath, outPath, password, false);
                }

            } catch (Exception ex) {
                Platform.runLater(() -> {
                    setStatus("Error: " + ex.getMessage());
                    disableButtons(false);
                });
            }
        });
    }

    private void startCrypto(Path inPath, Path outPath, char[] password, boolean encrypt) {
        CompletableFuture.runAsync(() -> {
            try {
                if (encrypt) {
                    CryptoService.encrypt(inPath, outPath, password);
                } else {
                    CryptoService.decrypt(inPath, outPath, password);
                }

                Platform.runLater(() -> {
                    progressBar.setProgress(1.0);

                    String statusMsg = encrypt ? "Encryption successful!" : "Decryption successful!";

                    // Verification Check
                    if (!encrypt) {
                        if (CryptoService.isEncryptedFile(outPath)) {
                            statusMsg += " WARNING: Output still seems encrypted (Double Encryption?).";

                            javafx.scene.control.Alert alert = new javafx.scene.control.Alert(
                                    javafx.scene.control.Alert.AlertType.WARNING);
                            alert.setTitle("Decryption Verification");
                            alert.setHeaderText("The decrypted file still looks like an encrypted file!");
                            alert.setContentText(
                                    "This can happen if the original file was encrypted multiple times.\n\nYou may need to decrypt this output file AGAIN using the correct password for the inner layer.");
                            alert.show();
                        }
                    }

                    setStatus(statusMsg);
                    // Log for the current user (privacy: users see their own logs)
                    DBController.logActivity(currentUser, encrypt ? "ENCRYPT" : "DECRYPT",
                            inPath.getFileName().toString());
                    loadLogs();

                    // Clear fields
                    inputFileField.clear();
                    outputFileField.clear();
                    passwordField.clear();
                    confirmPasswordField.clear();

                    // Open directory
                    try {
                        File outDir = outPath.getParent().toFile();
                        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                            Desktop.getDesktop().open(outDir);
                        }
                    } catch (IOException e) {
                        // Just log or ignore if we can't open the folder
                        e.printStackTrace();
                    }
                });
            } catch (IOException | GeneralSecurityException ex) {
                Platform.runLater(() -> setStatus("Error: " + ex.getMessage()));
            } finally {
                Arrays.fill(password, '\0');
                Platform.runLater(() -> disableButtons(false));
            }
        });
    }

    @FXML
    private void onGenerate() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++)
            sb.append(chars.charAt((int) (Math.random() * chars.length())));
        passwordField.setText(sb.toString());
        confirmPasswordField.setText(sb.toString());
        setStatus("Generated secure password");
    }

    @FXML
    private void onShowKeyToggle() {
        if (showKeyCheck.isSelected()) {
            passwordField.setPromptText(passwordField.getText());
            passwordField.setText("");
            confirmPasswordField.setPromptText(confirmPasswordField.getText());
            confirmPasswordField.setText("");
            setStatus("Warning: Showing keys is not implemented safely in JavaFX PasswordField");
        } else {
            setStatus("Key hidden");
        }
    }

    @FXML
    private void onAddUser() {
        if (!"admin".equals(currentUser)) {
            regStatusLabel.setText("Access Denied: Admin only.");
            return;
        }

        String newDeviceUser = regUsernameField.getText().trim();
        String pass = regPasswordField.getText();
        String conf = regConfirmPasswordField.getText();

        if (newDeviceUser.isEmpty() || pass.isEmpty()) {
            regStatusLabel.setText("All fields are required");
            return;
        }

        if (!pass.equals(conf)) {
            regStatusLabel.setText("Passwords do not match");
            return;
        }

        if (DBController.registerUser(newDeviceUser, pass)) {
            regStatusLabel.setText("User '" + newDeviceUser + "' created successfully!");
            regUsernameField.clear();
            regPasswordField.clear();
            regConfirmPasswordField.clear();
        } else {
            regStatusLabel.setText("Failed: Username might be taken.");
        }
    }

    @FXML
    public void loadLogs() {
        if (logsListView != null && currentUser != null) {
            logsListView.getItems().clear();
            // This pulls logs ONLY for the currentUser, ensuring privacy.
            logsListView.getItems().addAll(DBController.getLogs(currentUser));
        }
    }

    @FXML
    private void onLogout() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/Login.fxml"));
            Parent root = loader.load();
            Stage stage = (Stage) inputFileField.getScene().getWindow();
            stage.setScene(new Scene(root));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void onExit() {
        Platform.exit();
        System.exit(0);
    }

    private void disableButtons(boolean disable) {
        if (encryptButton != null)
            encryptButton.setDisable(disable);
        if (decryptButton != null)
            decryptButton.setDisable(disable);
        if (browseButton != null)
            browseButton.setDisable(disable);
        if (selectButton != null)
            selectButton.setDisable(disable);
        if (generateButton != null)
            generateButton.setDisable(disable);
    }

    private void setStatus(String msg) {
        if (statusText != null)
            statusText.setText(msg);
    }
}