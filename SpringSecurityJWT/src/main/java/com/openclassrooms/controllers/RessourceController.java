package com.openclassrooms.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RessourceController {
	@GetMapping("/")
	public String getResource() {
		return "a value...";
	}
}
