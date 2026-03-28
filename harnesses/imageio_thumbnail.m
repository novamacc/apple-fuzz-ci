/*
 * ImageIO Thumbnail Fuzzer - THE MONEY HARNESS
 *
 * CGImageSourceCreateThumbnailAtIndex is the EXACT function that
 * BlastDoor/iMessage calls to process incoming image attachments.
 * A crash here = zero-click remote code execution = $500K-$2M bounty.
 *
 * This also tests CGImageSourceCreateImageAtIndex with various options
 * that BlastDoor uses: kCGImageSourceCreateThumbnailFromImageAlways,
 * max pixel size, subsample factor.
 *
 * Reference: Project Zero "A Look at iMessage in iOS 14" (BlastDoor analysis)
 */
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

extern void CGRenderingStateSetAllowsAcceleration(void *, bool);

#undef MAX_INPUT
#define MAX_INPUT (2 * 1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        CFDataRef cfdata = CFDataCreateWithBytesNoCopy(
            kCFAllocatorDefault, data, size, kCFAllocatorNull);
        if (!cfdata) return 0;

        CGImageSourceRef src = CGImageSourceCreateWithData(cfdata, NULL);
        if (src) {
            /*
             * Test 1: Thumbnail generation (iMessage path)
             * BlastDoor requests thumbnails at various sizes for
             * notification previews and conversation view.
             */
            NSDictionary *thumbOpts = @{
                (id)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
                (id)kCGImageSourceCreateThumbnailWithTransform: @YES,
                (id)kCGImageSourceThumbnailMaxPixelSize: @(320),
                (id)kCGImageSourceShouldCache: @NO,
            };
            CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
                src, 0, (__bridge CFDictionaryRef)thumbOpts);
            if (thumb) {
                /* Force full decode by reading pixel data */
                size_t w = CGImageGetWidth(thumb);
                size_t h = CGImageGetHeight(thumb);
                if (w > 0 && h > 0 && w <= 4096 && h <= 4096) {
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    if (cs) {
                        CGContextRef ctx = CGBitmapContextCreate(
                            NULL, w, h, 8, w * 4, cs,
                            (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                                           kCGBitmapByteOrder32Big));
                        if (ctx) {
                            CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), thumb);
                            CGContextRelease(ctx);
                        }
                        CGColorSpaceRelease(cs);
                    }
                }
                CGImageRelease(thumb);
            }

            /*
             * Test 2: Larger thumbnail (full conversation image)
             */
            NSDictionary *largeOpts = @{
                (id)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
                (id)kCGImageSourceCreateThumbnailWithTransform: @YES,
                (id)kCGImageSourceThumbnailMaxPixelSize: @(1024),
                (id)kCGImageSourceShouldCache: @NO,
                (id)kCGImageSourceShouldAllowFloat: @YES,
            };
            CGImageRef large = CGImageSourceCreateThumbnailAtIndex(
                src, 0, (__bridge CFDictionaryRef)largeOpts);
            if (large) {
                size_t lw = CGImageGetWidth(large);
                size_t lh = CGImageGetHeight(large);
                if (lw > 0 && lh > 0 && lw <= 4096 && lh <= 4096) {
                    CGColorSpaceRef lcs = CGColorSpaceCreateDeviceRGB();
                    if (lcs) {
                        CGContextRef lctx = CGBitmapContextCreate(
                            NULL, lw, lh, 8, lw * 4, lcs,
                            (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                                           kCGBitmapByteOrder32Big));
                        if (lctx) {
                            CGContextDrawImage(lctx, CGRectMake(0, 0, lw, lh), large);
                            CGContextRelease(lctx);
                        }
                        CGColorSpaceRelease(lcs);
                    }
                }
                CGImageRelease(large);
            }

            /*
             * Test 3: Subsample factor (used for progressive decode)
             * This exercises a DIFFERENT code path than full decode.
             */
            NSDictionary *subOpts = @{
                (id)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
                (id)kCGImageSourceThumbnailMaxPixelSize: @(160),
                (id)kCGImageSourceSubsampleFactor: @(4),
                (id)kCGImageSourceShouldCache: @NO,
            };
            CGImageRef sub = CGImageSourceCreateThumbnailAtIndex(
                src, 0, (__bridge CFDictionaryRef)subOpts);
            if (sub) {
                size_t sw = CGImageGetWidth(sub);
                size_t sh = CGImageGetHeight(sub);
                if (sw > 0 && sh > 0 && sw <= 4096 && sh <= 4096) {
                    CGColorSpaceRef scs = CGColorSpaceCreateDeviceRGB();
                    if (scs) {
                        CGContextRef sctx = CGBitmapContextCreate(
                            NULL, sw, sh, 8, sw * 4, scs,
                            (CGBitmapInfo)(kCGImageAlphaPremultipliedLast |
                                           kCGBitmapByteOrder32Big));
                        if (sctx) {
                            CGContextDrawImage(sctx, CGRectMake(0, 0, sw, sh), sub);
                            CGContextRelease(sctx);
                        }
                        CGColorSpaceRelease(scs);
                    }
                }
                CGImageRelease(sub);
            }

            CFRelease(src);
        }
        CFRelease(cfdata);
    }
    return 0;
}
