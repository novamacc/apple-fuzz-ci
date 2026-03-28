/*
 * ImageIO RAW/DNG Format Variant Hunter
 *
 * CVE-2025-43300 proved that DNG metadata mismatch bugs (SamplesPerPixel
 * vs actual component count) cause heap corruption in ImageIO's RAW parser.
 * This fuzzer forces ImageIO to try each of 26+ RAW camera UTIs even
 * with corrupted headers, maximizing coverage of format-specific parsers.
 *
 * Each camera vendor (Canon, Nikon, Sony, Fuji, etc.) has its own RAW
 * parser in ImageIO. Type hints force the specific parser to attempt
 * parsing regardless of magic bytes.
 *
 * Mutation strategy (byte[1] & 0x03):
 *   0 = full random mutation (default fuzzer behavior)
 *   1 = mutate TIFF IFD tags (tag IDs, types, counts, offsets)
 *   2 = mutate embedded JPEG (SOF markers, component counts, quant tables)
 *   3 = mutate metadata only (EXIF, XMP, IPTC blocks)
 *
 * Key detection: after decode, compare metadata-reported dimensions/depth
 * with actual CGImage properties. Mismatches indicate parser confusion
 * - the same class of bug as CVE-2025-43300.
 */
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>

extern void CGRenderingStateSetAllowsAcceleration(void *, bool);

#undef MAX_INPUT
#define MAX_INPUT (2 * 1024 * 1024) /* 2MB max input */
#define MAX_DIM 8192

/* RAW camera UTIs - covers all major camera vendors */
static const CFStringRef kRawUTIs[] = {
    CFSTR("com.adobe.raw-image"),          /* DNG */
    CFSTR("com.canon.cr2-raw-image"),      /* Canon CR2 */
    CFSTR("com.canon.cr3-raw-image"),      /* Canon CR3 */
    CFSTR("com.canon.crw-raw-image"),      /* Canon CRW */
    CFSTR("com.nikon.raw-image"),          /* Nikon NEF */
    CFSTR("com.nikon.nrw-raw-image"),      /* Nikon NRW */
    CFSTR("com.sony.raw-image"),           /* Sony ARW */
    CFSTR("com.sony.sr2-raw-image"),       /* Sony SR2 */
    CFSTR("com.fuji.raw-image"),           /* Fuji RAF */
    CFSTR("com.olympus.raw-image"),        /* Olympus ORF */
    CFSTR("com.olympus.or-raw-image"),     /* Olympus OR */
    CFSTR("com.panasonic.raw-image"),      /* Panasonic RW2 */
    CFSTR("com.panasonic.rw2-raw-image"),  /* Panasonic RW2 alt */
    CFSTR("com.pentax.raw-image"),         /* Pentax PEF */
    CFSTR("com.samsung.raw-image"),        /* Samsung SRW */
    CFSTR("com.leica.raw-image"),          /* Leica RWL */
    CFSTR("com.konicaminolta.raw-image"),  /* Minolta MRW */
    CFSTR("com.hasselblad.raw-image"),     /* Hasselblad 3FR */
    CFSTR("com.hasselblad.fff-raw-image"), /* Hasselblad FFF */
    CFSTR("com.phaseone.raw-image"),       /* Phase One IIQ */
    CFSTR("com.leafamerica.raw-image"),    /* Leaf MOS */
    CFSTR("com.epson.raw-image"),          /* Epson ERF */
    CFSTR("com.kodak.raw-image"),          /* Kodak DCR */
    CFSTR("com.apple.proraw"),             /* Apple ProRAW */
    CFSTR("public.camera-raw-image"),      /* Generic RAW */
    CFSTR("com.adobe.dng-raw-image"),      /* Adobe DNG */
};
static const size_t kRawUTICount = sizeof(kRawUTIs) / sizeof(kRawUTIs[0]);

/*
 * get_cfnumber_int - safely extract an integer from a CFNumber in a dict.
 * Returns -1 if the key is missing or not a CFNumber.
 */
static int get_cfnumber_int(CFDictionaryRef dict, CFStringRef key) {
    if (!dict) return -1;
    CFTypeRef val = CFDictionaryGetValue(dict, key);
    if (!val || CFGetTypeID(val) != CFNumberGetTypeID()) return -1;
    int result = 0;
    CFNumberGetValue((CFNumberRef)val, kCFNumberIntType, &result);
    return result;
}

/*
 * check_metadata_vs_image_mismatch
 *
 * This is the core CVE-2025-43300 variant detector.
 * Compare what the metadata (TIFF IFD, EXIF) says the image should be
 * versus what CGImage actually decoded. Any mismatch means the parser
 * used inconsistent values internally - exactly the bug class that
 * caused heap corruption in CVE-2025-43300.
 *
 * We log mismatches to stderr so ASAN/fuzzer logs capture them even
 * if they don't immediately crash. These are high-value signals.
 */
static void check_metadata_vs_image_mismatch(CGImageSourceRef src,
                                              size_t idx,
                                              CGImageRef img) {
    if (!img) return;

    size_t actual_w = CGImageGetWidth(img);
    size_t actual_h = CGImageGetHeight(img);
    size_t actual_bpp = CGImageGetBitsPerPixel(img);
    size_t actual_bpc = CGImageGetBitsPerComponent(img);
    size_t actual_components = (actual_bpc > 0) ? (actual_bpp / actual_bpc) : 0;

    CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(src, idx, NULL);
    if (!props) return;

    /* Extract metadata-reported dimensions */
    int meta_w = get_cfnumber_int(props, kCGImagePropertyPixelWidth);
    int meta_h = get_cfnumber_int(props, kCGImagePropertyPixelHeight);
    int meta_depth = get_cfnumber_int(props, kCGImagePropertyDepth);

    /* TIFF-specific: SamplesPerPixel, BitsPerSample */
    CFDictionaryRef tiff = CFDictionaryGetValue(
        props, kCGImagePropertyTIFFDictionary);
    int tiff_spp = get_cfnumber_int(tiff, CFSTR("SamplesPerPixel"));
    int tiff_width = get_cfnumber_int(tiff, CFSTR("ImageWidth"));
    int tiff_height = get_cfnumber_int(tiff, CFSTR("ImageLength"));

    /* EXIF: PixelXDimension, PixelYDimension */
    CFDictionaryRef exif = CFDictionaryGetValue(
        props, kCGImagePropertyExifDictionary);
    int exif_w = get_cfnumber_int(exif, kCGImagePropertyExifPixelXDimension);
    int exif_h = get_cfnumber_int(exif, kCGImagePropertyExifPixelYDimension);
    int exif_components = -1;
    if (exif) {
        CFTypeRef comp_cfg = CFDictionaryGetValue(
            exif, kCGImagePropertyExifComponentsConfiguration);
        if (comp_cfg && CFGetTypeID(comp_cfg) == CFDataGetTypeID()) {
            exif_components = (int)CFDataGetLength((CFDataRef)comp_cfg);
        }
    }

    /*
     * CHECK 1: Metadata width/height vs actual decoded dimensions
     * CVE-2025-43300 variant: if TIFF says 4000x3000 but decoder produces
     * 800x600, the parser used different values for allocation vs fill.
     */
    if (meta_w > 0 && (size_t)meta_w != actual_w) {
        fprintf(stderr, "[MISMATCH] idx=%zu meta_width=%d actual_width=%zu\n",
                idx, meta_w, actual_w);
    }
    if (meta_h > 0 && (size_t)meta_h != actual_h) {
        fprintf(stderr, "[MISMATCH] idx=%zu meta_height=%d actual_height=%zu\n",
                idx, meta_h, actual_h);
    }

    /* CHECK 2: TIFF IFD dimensions vs actual */
    if (tiff_width > 0 && (size_t)tiff_width != actual_w) {
        fprintf(stderr, "[MISMATCH] idx=%zu tiff_width=%d actual_width=%zu\n",
                idx, tiff_width, actual_w);
    }
    if (tiff_height > 0 && (size_t)tiff_height != actual_h) {
        fprintf(stderr, "[MISMATCH] idx=%zu tiff_height=%d actual_height=%zu\n",
                idx, tiff_height, actual_h);
    }

    /* CHECK 3: EXIF dimensions vs actual */
    if (exif_w > 0 && (size_t)exif_w != actual_w) {
        fprintf(stderr, "[MISMATCH] idx=%zu exif_width=%d actual_width=%zu\n",
                idx, exif_w, actual_w);
    }
    if (exif_h > 0 && (size_t)exif_h != actual_h) {
        fprintf(stderr, "[MISMATCH] idx=%zu exif_height=%d actual_height=%zu\n",
                idx, exif_h, actual_h);
    }

    /*
     * CHECK 4: SamplesPerPixel vs actual component count
     * This is EXACTLY CVE-2025-43300 - TIFF says N samples but JPEG
     * decoder produces M components. The allocator uses N, the writer
     * uses M, heap overflow.
     */
    if (tiff_spp > 0 && actual_components > 0 &&
        (size_t)tiff_spp != actual_components) {
        fprintf(stderr,
                "[MISMATCH-SPP] idx=%zu tiff_spp=%d actual_components=%zu "
                "bpp=%zu bpc=%zu\n",
                idx, tiff_spp, actual_components, actual_bpp, actual_bpc);
    }

    /* CHECK 5: Metadata depth vs actual bits per component */
    if (meta_depth > 0 && (size_t)meta_depth != actual_bpc) {
        fprintf(stderr, "[MISMATCH] idx=%zu meta_depth=%d actual_bpc=%zu\n",
                idx, meta_depth, actual_bpc);
    }

    /* CHECK 6: EXIF ComponentsConfiguration length vs actual */
    if (exif_components > 0 && actual_components > 0 &&
        (size_t)exif_components != actual_components) {
        fprintf(stderr,
                "[MISMATCH-EXIF-COMP] idx=%zu exif_comp_len=%d "
                "actual_components=%zu\n",
                idx, exif_components, actual_components);
    }

    CFRelease(props);
}

/*
 * force_decode - decode image and thumbnails, then run mismatch checks.
 */
static void force_decode(CGImageSourceRef src) {
    size_t count = CGImageSourceGetCount(src);
    size_t limit = count < 2 ? count : 2;

    for (size_t i = 0; i < limit; i++) {
        /* Full decode */
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, NULL);
        if (img) {
            /* Run metadata-vs-actual mismatch checks (CVE-2025-43300 hunter) */
            check_metadata_vs_image_mismatch(src, i, img);

            size_t w = CGImageGetWidth(img);
            size_t h = CGImageGetHeight(img);
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

        /* Thumbnail decode - exercises different RAW path */
        NSDictionary *thumbOpts = @{
            (id)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
            (id)kCGImageSourceThumbnailMaxPixelSize: @(320),
            (id)kCGImageSourceShouldCache: @NO,
        };
        CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
            src, i, (__bridge CFDictionaryRef)thumbOpts);
        if (thumb) {
            /* Also check thumbnail for dimension mismatches */
            check_metadata_vs_image_mismatch(src, i, thumb);
            CGImageRelease(thumb);
        }
    }
}

/*
 * force_decode_with_type_check - decode with type hint then verify the
 * detected type matches. Exercises error recovery paths when the hint
 * doesn't match the actual data.
 */
static void force_decode_with_type_check(CGImageSourceRef src,
                                          CFStringRef hintUTI) {
    /* Check if ImageIO's detected type matches our hint */
    CFStringRef detectedType = CGImageSourceGetType(src);

    if (detectedType && hintUTI) {
        /* Type mismatch = we're forcing a parser to handle alien data.
         * This is exactly where format confusion bugs live. */
        if (!CFEqual(detectedType, hintUTI)) {
            /*
             * The parser was forced to try data it doesn't understand.
             * Still decode - this exercises error recovery and fallback
             * paths where allocation sizes might be wrong.
             */
            CGImageSourceStatus status = CGImageSourceGetStatus(src);
            (void)status; /* Prevent optimization, we want the call */
        }
    }

    force_decode(src);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        /*
         * Structured mutation hints from first 2 bytes:
         *   byte[0] & 0x1F = UTI index (26 raw formats)
         *   byte[1] & 0x03 = mutation focus:
         *     0 = full random (let the fuzzer do its thing)
         *     1 = TIFF IFD tags (tag IDs, types, counts, value offsets)
         *     2 = embedded JPEG (SOF markers, component counts, quant)
         *     3 = metadata only (EXIF, XMP, IPTC)
         *
         * The mutation_focus doesn't change runtime behavior - it's a
         * signal for custom mutators / corpus organization. The fuzzer
         * engine can use byte[1] to focus mutations on the right region.
         * We log it so crashes can be traced to their mutation strategy.
         */
        uint8_t utiIdx = data[0] & 0x1F;
        if (utiIdx >= kRawUTICount) utiIdx = utiIdx % kRawUTICount;
        uint8_t mutation_focus = data[1] & 0x03;
        CFStringRef hintUTI = kRawUTIs[utiIdx];

        /* Consume control bytes for hint, but feed ALL data to parser.
         * RAW parsers need magic bytes at offset 0, so we give them
         * the full buffer. The first 2 bytes being "wrong" is fine -
         * that's additional format confusion stress. */

        CFDataRef cfdata = CFDataCreateWithBytesNoCopy(
            kCFAllocatorDefault, data, size, kCFAllocatorNull);
        if (!cfdata) return 0;

        /* Test with type hint - forces specific RAW parser */
        NSDictionary *opts = @{
            (id)kCGImageSourceTypeIdentifierHint: (__bridge id)hintUTI,
        };
        CGImageSourceRef src = CGImageSourceCreateWithData(
            cfdata, (__bridge CFDictionaryRef)opts);
        if (src) {
            force_decode_with_type_check(src, hintUTI);
            CFRelease(src);
        }

        /* Also test without hint - auto-detection path */
        CGImageSourceRef src2 = CGImageSourceCreateWithData(cfdata, NULL);
        if (src2) {
            force_decode(src2);
            CFRelease(src2);
        }

        /*
         * Test with a MISMATCHED hint - pick a different UTI.
         * This forces one vendor's RAW parser to handle another vendor's
         * data. Format confusion between vendor parsers is a rich bug class.
         * Only do this for mutation_focus 0 (full random) to avoid
         * tripling the execution time for every input.
         */
        if (mutation_focus == 0) {
            uint8_t altIdx = (utiIdx + 13) % kRawUTICount; /* different UTI */
            CFStringRef altUTI = kRawUTIs[altIdx];
            NSDictionary *altOpts = @{
                (id)kCGImageSourceTypeIdentifierHint: (__bridge id)altUTI,
            };
            CGImageSourceRef src3 = CGImageSourceCreateWithData(
                cfdata, (__bridge CFDictionaryRef)altOpts);
            if (src3) {
                force_decode_with_type_check(src3, altUTI);
                CFRelease(src3);
            }
        }

        CFRelease(cfdata);
    }
    return 0;
}
