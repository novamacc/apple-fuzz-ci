/*
 * ImageIO Generic Fuzzer
 * Targets: ALL 62+ image formats supported by ImageIO
 * Bounty: $500K-$2M (zero-click via iMessage)
 *
 * This exercises the full decode path: parse headers, decode pixels,
 * render to bitmap context. Catches OOB reads/writes, heap corruption,
 * integer overflows in dimension calculations.
 */
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

/* Disable GPU acceleration to catch CPU-side bugs and avoid GPU hangs */
extern void CGRenderingStateSetAllowsAcceleration(void *, bool);

/* Maximum dimensions to prevent OOM from decompression bombs */
#define MAX_DIM 8192
#undef MAX_INPUT
#define MAX_INPUT (2 * 1024 * 1024) /* 2MB max input */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        CFDataRef cfdata = CFDataCreateWithBytesNoCopy(
            kCFAllocatorDefault, data, size, kCFAllocatorNull);
        if (!cfdata) return 0;

        /* Create image source without type hint - let ImageIO detect format */
        CGImageSourceRef src = CGImageSourceCreateWithData(cfdata, NULL);
        if (src) {
            size_t count = CGImageSourceGetCount(src);
            /* Process up to 4 frames (animated GIF/HEICS/AVIS) */
            size_t limit = count < 4 ? count : 4;

            for (size_t i = 0; i < limit; i++) {
                CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, NULL);
                if (img) {
                    size_t w = CGImageGetWidth(img);
                    size_t h = CGImageGetHeight(img);

                    /* Force full pixel decode via bitmap context */
                    if (w > 0 && h > 0 && w <= MAX_DIM && h <= MAX_DIM) {
                        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                        if (cs) {
                            CGContextRef ctx = CGBitmapContextCreate(
                                NULL, w, h, 8, w * 4, cs,
                                (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                                               kCGBitmapByteOrder32Big));
                            if (ctx) {
                                CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);
                                CGContextRelease(ctx);
                            }
                            CGColorSpaceRelease(cs);
                        }
                    }
                    CGImageRelease(img);
                }
            }
            CFRelease(src);
        }
        CFRelease(cfdata);
    }
    return 0;
}
