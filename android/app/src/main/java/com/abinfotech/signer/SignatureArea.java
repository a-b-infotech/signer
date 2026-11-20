package com.abinfotech.signer;

import android.graphics.RectF;
import com.itextpdf.text.Rectangle;

public class SignatureArea {
    public int pageNum;   // 1-based page number
    public float x;        // PDF X coordinate (from bottom-left)
    public float y;        // PDF Y coordinate (from bottom-left)
    public float width;    // Box width in PDF points
    public float height;   // Box height in PDF points

    public SignatureArea(int pageNum, float x, float y, float width, float height) {
        this.pageNum = pageNum;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    public RectF toRectF() {
        return new RectF(x, y, x + width, y + height);
    }

    public Rectangle toRectangle() {
        return new Rectangle(x, y, x + width, y + height);
    }

    @Override
    public String toString() {
        return "Page " + pageNum + " [X:" + (int) x + ", Y:" + (int) y + ", W:" + (int) width + ", H:" + (int) height + "]";
    }
}
