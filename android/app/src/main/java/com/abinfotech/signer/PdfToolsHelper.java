package com.abinfotech.signer;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Document;
import com.itextpdf.text.Element;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfCopy;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfGState;
import com.itextpdf.text.pdf.PdfImportedPage;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfNumber;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

public class PdfToolsHelper {

    /**
     * Password Protect (Encrypt) PDF using 128-bit AES
     */
    public static void protectPdf(File inputFile, File outputFile, String password) throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        PdfReader reader = new PdfReader(inputFile.getAbsolutePath());
        FileOutputStream fos = new FileOutputStream(outputFile);
        PdfStamper stamper = new PdfStamper(reader, fos);
        stamper.setEncryption(
                password.getBytes(),
                password.getBytes(),
                PdfWriter.ALLOW_PRINTING | PdfWriter.ALLOW_COPY,
                PdfWriter.ENCRYPTION_AES_128
        );
        stamper.close();
        fos.close();
        reader.close();
    }

    /**
     * Unlock PDF (Remove Password)
     */
    public static void unlockPdf(File inputFile, File outputFile, String password) throws Exception {
        byte[] pwdBytes = (password != null) ? password.getBytes() : new byte[0];
        PdfReader reader = new PdfReader(inputFile.getAbsolutePath(), pwdBytes);
        FileOutputStream fos = new FileOutputStream(outputFile);
        PdfStamper stamper = new PdfStamper(reader, fos);
        stamper.close();
        fos.close();
        reader.close();
    }

    /**
     * Add Watermark diagonally across all pages
     */
    public static void watermarkPdf(File inputFile, File outputFile, String watermarkText) throws Exception {
        if (watermarkText == null || watermarkText.trim().isEmpty()) {
            watermarkText = "CONFIDENTIAL";
        }
        PdfReader reader = new PdfReader(inputFile.getAbsolutePath());
        FileOutputStream fos = new FileOutputStream(outputFile);
        PdfStamper stamper = new PdfStamper(reader, fos);
        BaseFont font = BaseFont.createFont(BaseFont.HELVETICA_BOLD, BaseFont.WINANSI, BaseFont.NOT_EMBEDDED);
        PdfGState gstate = new PdfGState();
        gstate.setFillOpacity(0.3f);

        int totalPages = reader.getNumberOfPages();
        for (int i = 1; i <= totalPages; i++) {
            PdfContentByte over = stamper.getOverContent(i);
            over.saveState();
            over.setGState(gstate);
            over.setColorFill(BaseColor.GRAY);
            over.beginText();
            over.setFontAndSize(font, 46);
            Rectangle size = reader.getPageSizeWithRotation(i);
            float cx = size.getWidth() / 2f;
            float cy = size.getHeight() / 2f;
            over.showTextAligned(Element.ALIGN_CENTER, watermarkText, cx, cy, 45);
            over.endText();
            over.restoreState();
        }
        stamper.close();
        fos.close();
        reader.close();
    }

    /**
     * Split / Extract selected pages (e.g. "1-3, 5")
     */
    public static void splitPdf(File inputFile, File outputFile, String pageRanges) throws Exception {
        PdfReader reader = new PdfReader(inputFile.getAbsolutePath());
        int totalPages = reader.getNumberOfPages();
        List<Integer> pagesToExtract = parsePageRanges(pageRanges, totalPages);

        if (pagesToExtract.isEmpty()) {
            reader.close();
            throw new IllegalArgumentException("No valid pages selected to extract");
        }

        Document document = new Document();
        FileOutputStream fos = new FileOutputStream(outputFile);
        PdfCopy copy = new PdfCopy(document, fos);
        document.open();

        for (int pageNum : pagesToExtract) {
            if (pageNum >= 1 && pageNum <= totalPages) {
                PdfImportedPage importedPage = copy.getImportedPage(reader, pageNum);
                copy.addPage(importedPage);
            }
        }

        document.close();
        fos.close();
        reader.close();
    }

    /**
     * Rotate PDF pages by specified degrees (e.g. 90, 180, 270)
     */
    public static void rotatePdf(File inputFile, File outputFile, int degrees) throws Exception {
        PdfReader reader = new PdfReader(inputFile.getAbsolutePath());
        int totalPages = reader.getNumberOfPages();
        for (int i = 1; i <= totalPages; i++) {
            PdfDictionary page = reader.getPageN(i);
            PdfNumber rot = page.getAsNumber(PdfName.ROTATE);
            int currentRot = (rot == null) ? 0 : rot.intValue();
            page.put(PdfName.ROTATE, new PdfNumber((currentRot + degrees) % 360));
        }
        FileOutputStream fos = new FileOutputStream(outputFile);
        PdfStamper stamper = new PdfStamper(reader, fos);
        stamper.close();
        fos.close();
        reader.close();
    }

    private static List<Integer> parsePageRanges(String rangesStr, int maxPage) {
        List<Integer> result = new ArrayList<>();
        if (rangesStr == null || rangesStr.trim().isEmpty()) {
            for (int i = 1; i <= maxPage; i++) result.add(i);
            return result;
        }

        String[] parts = rangesStr.split("[,;]");
        for (String part : parts) {
            part = part.trim();
            if (part.contains("-")) {
                String[] bounds = part.split("-");
                if (bounds.length == 2) {
                    try {
                        int start = Integer.parseInt(bounds[0].trim());
                        int end = Integer.parseInt(bounds[1].trim());
                        for (int i = start; i <= end; i++) {
                            if (i >= 1 && i <= maxPage && !result.contains(i)) {
                                result.add(i);
                            }
                        }
                    } catch (NumberFormatException ignored) {}
                }
            } else {
                try {
                    int p = Integer.parseInt(part);
                    if (p >= 1 && p <= maxPage && !result.contains(p)) {
                        result.add(p);
                    }
                } catch (NumberFormatException ignored) {}
            }
        }
        return result;
    }
}
