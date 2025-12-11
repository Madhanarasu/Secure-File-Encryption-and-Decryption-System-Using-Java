package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.IOException;
import java.sql.Connection;
import java.util.concurrent.ExecutionException;


import javafx.concurrent.Task;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundFill;
import javafx.scene.layout.Border;
import javafx.scene.layout.BorderStroke;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;

/**
 * Hello world!
 *
 */
public class App 
{
public void start(Stage primaryStage) throws InterruptedException, ExecutionException, IOException {
		
		
		primaryStage.setTitle("FileGuardian");
		VBox root = new VBox();
        root.setAlignment(Pos.CENTER);

	
		Label login = new Label("LOGIN ");
		
		
		login.setFont(Font.font("System", FontWeight.BOLD, 25));
		Label UserName_l = new Label("Username");

		UserName_l.setFont(Font.font("System", FontWeight.BOLD, 20));
		Label Password_l = new Label("Password");

		Password_l.setFont(Font.font("System", FontWeight.BOLD, 20));
		TextField UserName_tx  = new TextField();
		UserName_tx.setMaxSize(300,350);

	   UserName_tx.setFont(Font.font("System",FontWeight.SEMI_BOLD, 14));
	   
		PasswordField password_tx = new PasswordField();
		password_tx.setMaxSize(300,350);

		UserName_l.setLabelFor(UserName_tx);
		Password_l.setLabelFor(password_tx);
		password_tx.setFont(Font.font("System",FontWeight.SEMI_BOLD, 14));
	    Button open = new Button("Login");

	    Button clear = new Button("Clear");
	    open.setBackground( new Background(new BackgroundFill(Color.LIGHTYELLOW,null,Insets.EMPTY)));
	    clear.setBackground( new Background(new BackgroundFill(Color.LIGHTYELLOW,null,Insets.EMPTY)));

	    clear.setBorder(new Border( new BorderStroke(Color.AQUA,null,null, null)));
	    Label  feedback_l = new Label();

	    feedback_l.setFont(Font.font("System",FontWeight.SEMI_BOLD,16));
	   HBox line1 = new HBox(20);
	   line1.getChildren().addAll(UserName_l,UserName_tx);
	   HBox line2 = new HBox(25);
	   line2.getChildren().addAll(Password_l,password_tx);
	   HBox line3 = new HBox(20);
	   line3.getChildren().addAll(open,clear);
	  line1.setAlignment(Pos.CENTER);
	  line2.setAlignment(Pos.CENTER);
	  line3.setAlignment(Pos.CENTER);
	  root.setSpacing(20);

	    root.getChildren().addAll(login,line1,line2,line3,feedback_l);
	   

		
		
		
	    
		Scene scene = new Scene(root,800,700);	
		primaryStage.setScene(scene);
		primaryStage.setResizable(false);
//		  Task<Connection> connection = new Task<>() {
		       	
//				@Override
//				protected Connection call() throws Exception {
//					Connection con = DbConnector.connect();
//					return con;
				
			
	//			}
				

//		  };	
				
				
//				new Thread(connection).start();
//				Connection con = connection.get();
				
		 
				
//		  open.setOnAction(e ->{});
//			  String UserName = UserName_tx.getText().strip();
//				 String Password =  password_tx.getText().strip();
//			 Boolean result;
//			if(( result =UserDAO.ValidateUser(con,UserName, Password)) != null) { 
////				result ==
//					try{if( true) {
////			  primaryStage.setScene(dashscene);	
//					
//						Parent	root1 = FXMLLoader.load(getClass().getResource("UI-1.fxml"));
//						
//						Scene scene1 = new Scene(root1);
//						primaryStage.setScene(scene1);
//						} else{
//					feedback_l.setText("Login Failed:Enter correct credentials");
//				}}catch (IOException e1) {
//							// TODO Auto-generated catch block
//							e1.printStackTrace();
//						}
//				}//Logging In
//			 else{feedback_l.setText("Failed to connect to the Database");}
//		  });      
//		   
//		  clear.setOnAction(e ->{
//			  UserName_tx.clear();
//			  password_tx.clear();
//		  });
		 
}}