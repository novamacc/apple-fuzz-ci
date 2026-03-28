/*
 * CoreText Font Parsing Fuzzer
 *
 * Targets fontd - the font daemon runs with NO sandbox and has
 * Full Disk Access. A crash in font parsing = sandbox escape potential.
 *
 * Font parsing is extremely complex: TrueType/OpenType tables (GSUB, GPOS,
 * morx, kern, cmap), AAT state machines, WOFF/WOFF2 decompression.
 * CTFramesetterCreateFrame triggers the FULL text layout pipeline:
 * shaping, kerning, ligature substitution, mark positioning.
 *
 * All CF-based (pure C API), use CFRelease for cleanup.
 */
#import <Foundation/Foundation.h>
#import <CoreText/CoreText.h>
#import <CoreGraphics/CoreGraphics.h>

#undef MAX_INPUT
#define MAX_INPUT (512 * 1024) /* 512KB max for fonts */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        /* Create font from raw bytes */
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return 0;

        CGFontRef cgFont = CGFontCreateWithDataProvider(provider);
        CGDataProviderRelease(provider);
        if (!cgFont) return 0;

        CTFontRef ctFont = CTFontCreateWithGraphicsFont(
            cgFont, 24.0, NULL, NULL);
        CGFontRelease(cgFont);
        if (!ctFont) return 0;

        /* Exercise font metrics - triggers head/hhea/OS2 table parsing */
        CGFloat ascent = CTFontGetAscent(ctFont);
        CGFloat descent = CTFontGetDescent(ctFont);
        CGFloat leading = CTFontGetLeading(ctFont);
        (void)ascent; (void)descent; (void)leading;

        /* Get glyph count - triggers maxp table */
        CFIndex glyphCount = CTFontGetGlyphCount(ctFont);
        (void)glyphCount;

        /* Create attributed string with the fuzzed font.
         * Short string (20 chars) is sufficient - we're fuzzing the font
         * parser, not the layout engine. Font tables (cmap, GSUB, GPOS,
         * kern, morx) are exercised regardless of string length. Keeping
         * it short avoids expensive layout computation in CTFramesetter. */
        CFStringRef testStr = CFSTR("ABcd\xC3\xA9\xC3\xB1" "09!@#$%^&*(");
        CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 2,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks);
        if (!attrs) {
            CFRelease(ctFont);
            return 0;
        }
        CFDictionarySetValue(attrs, kCTFontAttributeName, ctFont);

        CFAttributedStringRef attrStr = CFAttributedStringCreate(
            kCFAllocatorDefault, testStr, attrs);
        CFRelease(attrs);
        if (!attrStr) {
            CFRelease(ctFont);
            return 0;
        }

        /* CTFramesetterCreateFrame - triggers FULL layout pipeline:
         * cmap lookup, GSUB substitution, GPOS positioning, kern,
         * morx AAT state machine, mark attachment */
        CTFramesetterRef framesetter = CTFramesetterCreateWithAttributedString(attrStr);
        if (framesetter) {
            CGMutablePathRef path = CGPathCreateMutable();
            if (path) {
                CGPathAddRect(path, NULL, CGRectMake(0, 0, 500, 500));
                CTFrameRef frame = CTFramesetterCreateFrame(
                    framesetter, CFRangeMake(0, 0), path, NULL);
                if (frame) {
                    /* Get lines and run through glyph access */
                    CFArrayRef lines = CTFrameGetLines(frame);
                    if (lines && CFArrayGetCount(lines) > 0) {
                        CTLineRef line = (CTLineRef)CFArrayGetValueAtIndex(lines, 0);
                        if (line) {
                            /* Trigger glyph bounds computation */
                            CGFloat lineAscent, lineDescent, lineLeading;
                            CTLineGetTypographicBounds(line, &lineAscent,
                                &lineDescent, &lineLeading);

                            /* Get glyph runs - exercises GSUB/GPOS results */
                            CFArrayRef runs = CTLineGetGlyphRuns(line);
                            if (runs && CFArrayGetCount(runs) > 0) {
                                CTRunRef run = (CTRunRef)CFArrayGetValueAtIndex(runs, 0);
                                CFIndex runGlyphCount = CTRunGetGlyphCount(run);
                                (void)runGlyphCount;
                            }
                        }
                    }
                    CFRelease(frame);
                }
                CGPathRelease(path);
            }
            CFRelease(framesetter);
        }

        /* Also test CTLineCreateWithAttributedString directly */
        CTLineRef line = CTLineCreateWithAttributedString(attrStr);
        if (line) {
            CGFloat la, ld, ll;
            double width = CTLineGetTypographicBounds(line, &la, &ld, &ll);
            (void)width;

            /* Trigger offset computation */
            CFIndex idx = CTLineGetStringIndexForPosition(line,
                CGPointMake(50.0, 0.0));
            (void)idx;

            CFRelease(line);
        }

        CFRelease(attrStr);
        CFRelease(ctFont);
    }
    return 0;
}
