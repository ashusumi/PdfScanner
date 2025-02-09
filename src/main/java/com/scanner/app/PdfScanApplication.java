package com.scanner.app;

import java.io.IOException;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.action.PdfAction;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;

@SpringBootApplication
public class PdfScanApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(PdfScanApplication.class, args);
//		 String filePath = "C://Users//LSPL355-pc//Desktop//malicious_test.pdf";
//	        createMaliciousPdf(filePath);
//	        System.out.println("Malicious PDF created: " + filePath);
	}

//	public static void createMaliciousPdf(String filePath) throws IOException {
//        PdfWriter writer = new PdfWriter(filePath);
//        PdfDocument pdfDoc = new PdfDocument(writer);
//        Document document = new Document(pdfDoc);
//
//        // Add normal content
//        document.add(new Paragraph("This is a test PDF containing document-level JavaScript."));
//
//        // Embed JavaScript at the document level
//        String jsScript = "app.alert('This is a test JavaScript execution in a PDF!');";
//        PdfAction jsAction = PdfAction.createJavaScript(jsScript);
//        pdfDoc.getCatalog().setOpenAction(jsAction);
//
//        document.close();
//        pdfDoc.close();
//    }
}

