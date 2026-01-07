package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


public class DBController { 
	
	static Connection con = null;
	public static Connection connect() {
		String url = "jdbc:sqlite:Secure-File-Encryption-and-Decryption-System-Using-Java\\src\\main\\java\\in\\madhan\\Secure_File_Encryption_and_Decryption_System_Using_Java\\FileGuardian.db";
		
	    try {
	     con =  DriverManager.getConnection(url);
	    	 System.out.println("Connection is formed") ;  		
	    }
	    catch(SQLException e)
	    {System.out.println("Conncection is not formed due to"+e.getMessage());}
		return con;
	    
		}
  private  static Boolean ValidateUser(String UserName,String Password) {
		
		
		String st = "SELECT Username,Password FROM Users WHERE Username=? AND Password=? ";
		if(con != null) {
		try(PreparedStatement stm = con.prepareStatement(st);){
		
		stm.setString(1,UserName);
		stm.setString(2, Password);
		ResultSet rs = stm.executeQuery();
		if(rs.next()) {return true;}
		else {
		return false;}}
	catch(SQLException e)	{ 
		
		return false;
	}}
		else {
		return null;}
		
		
	
	}
}
