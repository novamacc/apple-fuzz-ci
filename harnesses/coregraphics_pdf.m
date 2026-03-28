/*
 * CoreGraphics PDF/JBIG2 Fuzzer (FORCEDENTRY class)
 *
 * NSO Group's FORCEDENTRY exploit used a vulnerability in the JBIG2
 * decoder embedded within CoreGraphics PDF rendering. PDFs containing
 * JBIG2 streams are processed by iMessage with NO user interaction.
 *
 * This fuzzer targets:
 * - PDF object stream parsing
 * - JBIG2 embedded image decoding
 * - Font subsetting within PDFs
 * - Encrypted PDF handling (CGPDFDocumentUnlockWithPassword)
 * - Page tree traversal
 *
 * A crash here is FORCEDENTRY-tier: $500K-$2M.
 */
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

extern void CGRenderingStateSetAllowsAcceleration(void *, bool);

#undef MAX_INPUT
#define MAX_INPUT (5 * 1024 * 1024) /* 5MB max for PDFs */
#define MAX_PAGES 3
#define PAGE_W 612  /* US Letter width in points */
#define PAGE_H 792  /* US Letter height in points */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return 0;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return 0;

        /* Handle encrypted PDFs - try empty password */
        if (CGPDFDocumentIsEncrypted(doc)) {
            if (!CGPDFDocumentIsUnlocked(doc)) {
                CGPDFDocumentUnlockWithPassword(doc, "");
                /* Also try null password */
                if (!CGPDFDocumentIsUnlocked(doc)) {
                    CGPDFDocumentUnlockWithPassword(doc, "password");
                }
            }
        }

        /* Allow access even if locked - some pages may still render */
        bool allowsAccess = CGPDFDocumentAllowsPrinting(doc) ||
                            CGPDFDocumentAllowsCopying(doc);
        (void)allowsAccess;

        size_t pageCount = CGPDFDocumentGetNumberOfPages(doc);
        size_t limit = pageCount < MAX_PAGES ? pageCount : MAX_PAGES;

        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        if (!cs) {
            CGPDFDocumentRelease(doc);
            return 0;
        }

        for (size_t i = 1; i <= limit; i++) {
            /* PDF pages are 1-indexed (not 0-indexed) */
            CGPDFPageRef page = CGPDFDocumentGetPage(doc, i);
            if (!page) continue;
            /* Note: page is a borrowed reference - do NOT release */

            /* Get page dimensions */
            CGRect mediaBox = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
            size_t pw = (size_t)mediaBox.size.width;
            size_t ph = (size_t)mediaBox.size.height;
            if (pw == 0 || ph == 0) { pw = PAGE_W; ph = PAGE_H; }
            if (pw > 4096) pw = 4096;
            if (ph > 4096) ph = 4096;

            /* Render page to bitmap - triggers full PDF rendering pipeline:
             * object parsing, stream decompression (FlateDecode, JBIG2Decode,
             * DCTDecode, CCITTFaxDecode), font rendering, color conversion */
            CGContextRef ctx = CGBitmapContextCreate(
                NULL, pw, ph, 8, pw * 4, cs,
                (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                               kCGBitmapByteOrder32Big));
            if (ctx) {
                /* White background */
                CGContextSetRGBFillColor(ctx, 1.0, 1.0, 1.0, 1.0);
                CGContextFillRect(ctx, CGRectMake(0, 0, pw, ph));

                /* Render the page */
                CGContextDrawPDFPage(ctx, page);

                /* Extract rendered bitmap to force complete decode */
                CGImageRef rendered = CGBitmapContextCreateImage(ctx);
                if (rendered) CGImageRelease(rendered);

                CGContextRelease(ctx);
            }

            /* Also extract page dictionary to exercise object parser */
            CGPDFDictionaryRef pageDict = CGPDFPageGetDictionary(page);
            if (pageDict) {
                /* Try to access Resources - triggers recursive parsing */
                CGPDFDictionaryRef resources = NULL;
                CGPDFDictionaryGetDictionary(pageDict, "Resources", &resources);

                /* Try to access Annots array */
                CGPDFArrayRef annots = NULL;
                CGPDFDictionaryGetArray(pageDict, "Annots", &annots);
                if (annots) {
                    size_t annotCount = CGPDFArrayGetCount(annots);
                    size_t annotLimit = annotCount < 10 ? annotCount : 10;
                    for (size_t j = 0; j < annotLimit; j++) {
                        CGPDFDictionaryRef annot = NULL;
                        CGPDFArrayGetDictionary(annots, j, &annot);
                        (void)annot;
                    }
                }
            }
        }

        CGColorSpaceRelease(cs);
        CGPDFDocumentRelease(doc);
    }
    return 0;
}
