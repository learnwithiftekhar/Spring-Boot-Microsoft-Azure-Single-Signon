package com.learnwithiftekhar.springMicrosoftSso.controller;


import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class IndexController {

    @GetMapping
    public String index(Model model, Authentication user) {
        model.addAttribute("user", user);
        return "index";
    }
}
