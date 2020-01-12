package com.pluralsight.security.controller;


import com.pluralsight.security.userdetails.UserInfo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserInfoController {

//	@GetMapping("/userinfo")
//	public UserInfo userInfo(@AuthenticationPrincipal MFAUser principal) {
//		return new UserInfo(principal.getUsername(), principal.getFirstName(), principal.getLastName(), principal.getEmail());
//	}

    @GetMapping("/userinfo")
    public UserInfo userInfo(Principal principal) {
        return new UserInfo(principal.getName(), "Joe", "Smith", "joe@email.com");
    }
}
