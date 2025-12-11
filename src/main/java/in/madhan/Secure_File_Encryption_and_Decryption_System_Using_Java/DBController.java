package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DBController {
	public static Connection connect() {
		String url = "jdbc:sqlite:Secure-File-Encryption-and-Decryption-System-Using-Java\\src\\main\\java\\in\\madhan\\Secure_File_Encryption_and_Decryption_System_Using_Java\\FileGuardian.db";
		 Connection con = null;
	    try {
	     con =  DriverManager.getConnection(url);
	    	 System.out.println("Connection is formed") ;  		
	    }
	    catch(SQLException e)
	    {System.out.println("Conncection is not formed due to"+e.getMessage());}
		return con;
	    
		}
}
