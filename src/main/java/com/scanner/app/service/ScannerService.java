package com.scanner.app.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;
import com.itextpdf.kernel.pdf.canvas.parser.PdfTextExtractor;

import java.io.IOException;
import java.util.List;
@Service
public class ScannerService {


	public String scanPdf(MultipartFile file) throws Exception { 
	    try {
	        if (containsMaliciousJavaScript(file)) {
	            return "❌ Invalid PDF: Contains Malicious JavaScript!";
	        } else {
	            return "✅ Valid PDF: No threats detected.";
	        }
	    } catch (Exception e) {
	        return "⚠️ Error: Could not process the PDF.";
	    }
	}

	
	private boolean containsMaliciousJavaScript(MultipartFile file) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(file.getInputStream()));

        // 1. Scan Document-Level JavaScript
        if (checkDocumentLevelJavaScript(pdfDoc)) {
            return true;
        }

        // 2. Scan Page Content and Annotations
        for (int i = 1; i <= pdfDoc.getNumberOfPages(); i++) {
            PdfPage page = pdfDoc.getPage(i);

            // Scan for JavaScript in Annotations
            if (checkAnnotationsForJavaScript(page)) {
                return true;
            }

            // Scan Page Content for Embedded JavaScript
            if (checkPageContentForJavaScript(page)) {
                return true;
            }
        }

        pdfDoc.close();
        return false;
    }

	private boolean checkDocumentLevelJavaScript(PdfDocument pdfDoc) {
	    PdfDictionary catalog = pdfDoc.getCatalog().getPdfObject();

	    // 1️⃣ Check if JavaScript exists inside Names dictionary
	    PdfDictionary names = catalog.getAsDictionary(PdfName.Names);
	    if (names != null) {
	        PdfDictionary jsNames = names.getAsDictionary(PdfName.JavaScript);
	        if (jsNames != null) {
	            System.out.println("JavaScript found in document catalog Names.");
	            return true;
	        }
	    }

	    // 2️⃣ Check if JavaScript exists inside OpenAction (document-level scripts)
	    PdfDictionary openAction = catalog.getAsDictionary(PdfName.OpenAction);
	    if (openAction != null) {
	        PdfName actionType = openAction.getAsName(PdfName.S);
	        if (PdfName.JavaScript.equals(actionType)) {
	            String jsCode = openAction.getAsString(PdfName.JS).toString();
	            if (isSuspiciousJavaScript(jsCode)) {
	                System.out.println("JavaScript found in document OpenAction: " + jsCode);
	                return true;
	            }
	        }
	    }

	    return false;
	}


    private boolean checkAnnotationsForJavaScript(PdfPage page) {
        List<PdfAnnotation> annotations = page.getAnnotations();
        for (PdfAnnotation annotation : annotations) {
            if (annotation instanceof PdfWidgetAnnotation) {
                PdfWidgetAnnotation widget = (PdfWidgetAnnotation) annotation;
                PdfDictionary annotationDict = widget.getPdfObject();
                PdfDictionary actionDict = annotationDict.getAsDictionary(PdfName.A);

                if (actionDict != null) {
                    PdfName actionType = actionDict.getAsName(PdfName.S);
                    if (PdfName.JavaScript.equals(actionType)) {
                        String jsCode = actionDict.getAsString(PdfName.JS).toString();
                        if (isSuspiciousJavaScript(jsCode)) {
                            System.out.println("JavaScript found in annotation: " + jsCode);
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean checkPageContentForJavaScript(PdfPage page) {
        try {
            String extractedText = PdfTextExtractor.getTextFromPage(page);
            if (isSuspiciousJavaScript(extractedText)) {
                System.out.println("JavaScript found in page content: " + extractedText);
                return true;
            }
        } catch (Exception e) {
            System.err.println("Error extracting text from page: " + e.getMessage());
        }
        return false;
    }

    private boolean isSuspiciousJavaScript(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }

        // Dangerous JavaScript patterns often used in PDF attacks
        String[] dangerousPatterns = {
            "eval", "app.launchURL", "this.exportDataObject", "submitForm", "getAnnots", "util.printf",
            "importScript", "setTimeOut", "setInterval", "document.write", "XMLHttpRequest", "createElement",
            "navigator", "window.open","window.alert", "location.href", "fetch", "Function","app.alert"
        };

        for (String pattern : dangerousPatterns) {
            if (content.toLowerCase().contains(pattern)) {
                return true; // Found dangerous JavaScript commands
            }
        }
        
        return false;
    }
}