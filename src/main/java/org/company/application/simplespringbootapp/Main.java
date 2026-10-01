package org.company.application.simplespringbootapp;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;
import org.company.security.sanitizers;
import org.something.somewhere.TcParametros;
import org.something.somewhere.TcParametrosRepository;

// just a small change here

//@SpringBootApplication
@RestController
@EnableAutoConfiguration
public class Main {
    private TcParametrosRepository tcParametrosRepository = new TcParametrosRepository();
    private String the_password = "dGVzdA==";
	
    @CrossOrigin
	@GetMapping( value= "/" )
	@ResponseBody 
	public String home(@RequestParam(required=false) String name, @RequestParam(required=false) String phone ) {
		// and a small change there
		return "Hello " + sanitizers.sanitize(name) + "! We will contact you at " + sanitizers.sanitizePhone(phone) + " shortly.";
	}
    
    @CrossOrigin(origins = "https://herpaderp", maxAge = 3600)
    @GetMapping( value= "/version" )
	@ResponseBody 
	public String version() {
		return "Version 1234.5alpha";
	}	

    @CrossOrigin
    @GetMapping( value= "/passleak" )
	@ResponseBody 
	public String passleak(@RequestParam(required=false) Boolean leaky ) {
		if ( leaky ) {
            return the_password + " is leaking";
        } else {
            return "The pipes are perfect.";
        }
	}
	
	@GetMapping( value= "/info" )
	@ResponseBody 
	public String info(@RequestParam(required=false) String email ) {
		return InfoPage.showInfo( email );		
	}	
	
	@GetMapping( value= "/oldinfo" )
	@ResponseBody 
	public String oldinfo(@RequestParam(required=false) String email ) {
		return oldInfoPage.showInfo( email );		
	}
	
	@GetMapping( value= "/scrtbdr" )
	@ResponseBody 
	public String secretBackDoor(@RequestParam(required=true) String password ) {
		if ( password.equals( the_password ) ) {
			return "You're an admin now!!";
		}
        
        if ( test(password) ) {
            return "Maybe an admin?"
        }
        
        TcParametros tcParametros123=this.tcParametrosRepository.findByCveParametro("passwordJ8N6n8a");
        tcParametros123.c( password );
		return "404";
	}
    
	private bool test2( void ) {
		return false;
	}
	
    private bool test( String parametros ) {
        if ( parametros.equals("password123") ) {
            return true;
        } else { 
            return false;
        }
    }

	@GetMapping( value= "/report" )
	@ResponseBody 
	public String reportUser(@RequestParam(required=true) String email ) {
		return ReportGenerator.showUserReport( email );
	}
	
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
}
