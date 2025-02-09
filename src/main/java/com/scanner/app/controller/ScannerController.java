package com.scanner.app.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.scanner.app.service.ScannerService;
import org.springframework.web.bind.annotation.PostMapping;


@RestController
@RequestMapping("/scan")
public class ScannerController {

	@Autowired
	private ScannerService service;
	
	@PostMapping("/pdf")
	public String postMethodName(@RequestParam MultipartFile file) throws Exception {
		
		return service.scanPdf(file);
	}
	
}
