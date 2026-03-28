/*
 * CoreAudio Codec Fuzzer (in-memory, NO temp files)
 *
 * Audio codecs (AAC, ALAC, MP3, FLAC, Opus) are reachable via iMessage
 * voice messages and ringtones. Uses AudioFileOpenWithCallbacks for
 * in-memory fuzzing - no filesystem overhead.
 *
 * Also tests AudioFileStreamOpen + AudioFileStreamParseBytes for the
 * streaming parse path (used by AirPlay, FaceTime, Music streaming).
 *
 * The callback-based approach feeds raw fuzz bytes directly to the
 * audio file parser without any temp file intermediary.
 */
#import <Foundation/Foundation.h>
#import <AudioToolbox/AudioToolbox.h>

#undef MAX_INPUT
#define MAX_INPUT (1 * 1024 * 1024) /* 1MB max for audio */
#define MAX_PACKETS 1024

/* In-memory read context */
typedef struct {
    const uint8_t *data;
    size_t size;
} FuzzData;

/* AudioFile callback: read bytes from memory buffer */
static OSStatus readProc(void *inClientData, SInt64 inPosition,
                          UInt32 requestCount, void *buffer,
                          UInt32 *actualCount) {
    FuzzData *fuzz = (FuzzData *)inClientData;
    if (inPosition < 0 || (size_t)inPosition >= fuzz->size) {
        *actualCount = 0;
        return kAudioFilePositionError;
    }
    size_t available = fuzz->size - (size_t)inPosition;
    UInt32 toRead = (requestCount < available) ? requestCount : (UInt32)available;
    memcpy(buffer, fuzz->data + inPosition, toRead);
    *actualCount = toRead;
    return noErr;
}

/* AudioFile callback: return size of data */
static SInt64 getSizeProc(void *inClientData) {
    FuzzData *fuzz = (FuzzData *)inClientData;
    return (SInt64)fuzz->size;
}

/* AudioFileStream callbacks (streaming path) */
static void streamPropertyProc(void *inClientData,
                                AudioFileStreamID inAudioFileStream,
                                AudioFileStreamPropertyID inPropertyID,
                                AudioFileStreamPropertyFlags *ioFlags) {
    /* Just trigger property parsing - any crash here is a bug */
    UInt32 propSize = 0;
    AudioFileStreamGetPropertyInfo(inAudioFileStream, inPropertyID,
                                    &propSize, NULL);
    if (propSize > 0 && propSize < 65536) {
        void *propData = malloc(propSize);
        if (propData) {
            AudioFileStreamGetProperty(inAudioFileStream, inPropertyID,
                                        &propSize, propData);
            free(propData);
        }
    }
}

static void streamPacketsProc(void *inClientData, UInt32 inNumberBytes,
                               UInt32 inNumberPackets,
                               const void *inInputData,
                               AudioStreamPacketDescription *inPacketDescriptions) {
    /* Packet data received - touch it to trigger any lazy parsing */
    (void)inNumberBytes;
    (void)inNumberPackets;
    (void)inInputData;
    (void)inPacketDescriptions;
}

/*
 * Determine AudioFileTypeID from magic bytes to skip expensive format
 * auto-detection. AudioFile probes every registered codec when hint=0;
 * providing the correct hint skips that scan entirely.
 */
static AudioFileTypeID guessTypeFromMagic(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    /* AMR: "#!AMR" (0x2321414D) */
    if (data[0] == '#' && data[1] == '!' && data[2] == 'A' && data[3] == 'M')
        return kAudioFileAMRType;

    /* RIFF header -> WAV */
    if (data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F')
        return kAudioFileWAVEType;

    /* AIFF: "FORM" with AIFF/AIFC */
    if (data[0] == 'F' && data[1] == 'O' && data[2] == 'R' && data[3] == 'M') {
        if (size >= 12) {
            if (data[8] == 'A' && data[9] == 'I' && data[10] == 'F')
                return kAudioFileAIFFType;
        }
        return kAudioFileAIFFType;
    }

    /* fLaC -> FLAC */
    if (data[0] == 'f' && data[1] == 'L' && data[2] == 'a' && data[3] == 'C')
        return kAudioFileFLACType;

    /* ID3 tag or 0xFF sync -> MP3 */
    if ((data[0] == 'I' && data[1] == 'D' && data[2] == '3') ||
        (data[0] == 0xFF && (data[1] & 0xE0) == 0xE0))
        return kAudioFileMP3Type;

    /* "caff" -> CAF */
    if (data[0] == 'c' && data[1] == 'a' && data[2] == 'f' && data[3] == 'f')
        return kAudioFileCAFType;

    /* MP4/M4A: check for ftyp box */
    if (size >= 8 && data[4] == 'f' && data[5] == 't' && data[6] == 'y' && data[7] == 'p')
        return kAudioFileM4AType; /* covers AAC/ALAC in MP4 container */

    /* OggS -> try as audio container */
    /* No direct kAudioFileOgg, fall through to auto-detect */

    return 0; /* unknown - let AudioFile auto-detect */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12 || size > MAX_INPUT) return -1;

    @autoreleasepool {
        FuzzData fuzz = { .data = data, .size = size };

        /*
         * Path 1: AudioFileOpenWithCallbacks (file-based parsing)
         * Use magic-byte hint to skip expensive format auto-detection.
         * Falls back to hint=0 (auto-detect) for unknown formats.
         */
        AudioFileTypeID typeHint = guessTypeFromMagic(data, size);

        AudioFileID audioFile = NULL;
        OSStatus err = AudioFileOpenWithCallbacks(
            &fuzz, readProc, NULL, getSizeProc, NULL,
            typeHint,
            &audioFile);

        if (err == noErr && audioFile) {
            /* Get the data format */
            AudioStreamBasicDescription asbd;
            UInt32 asbdSize = sizeof(asbd);
            err = AudioFileGetProperty(audioFile,
                kAudioFilePropertyDataFormat, &asbdSize, &asbd);

            if (err == noErr) {
                /* Get packet count */
                UInt64 packetCount = 0;
                UInt32 pcSize = sizeof(packetCount);
                AudioFileGetProperty(audioFile,
                    kAudioFilePropertyAudioDataPacketCount,
                    &pcSize, &packetCount);

                /* Get maximum packet size */
                UInt32 maxPacketSize = 0;
                UInt32 mpsSize = sizeof(maxPacketSize);
                AudioFileGetProperty(audioFile,
                    kAudioFilePropertyMaximumPacketSize,
                    &mpsSize, &maxPacketSize);

                /* Read packet data - triggers actual codec parsing */
                if (maxPacketSize > 0 && maxPacketSize < 65536) {
                    UInt32 numPackets = MAX_PACKETS;
                    if (packetCount > 0 && packetCount < numPackets)
                        numPackets = (UInt32)packetCount;

                    UInt32 bufSize = numPackets * maxPacketSize;
                    if (bufSize > 4 * 1024 * 1024) bufSize = 4 * 1024 * 1024;

                    void *buf = malloc(bufSize);
                    AudioStreamPacketDescription *pktDescs = malloc(
                        numPackets * sizeof(AudioStreamPacketDescription));

                    if (buf && pktDescs) {
                        UInt32 ioNumPackets = numPackets;
                        UInt32 ioNumBytes = bufSize;
                        AudioFileReadPacketData(audioFile, false, &ioNumBytes,
                            pktDescs, 0, &ioNumPackets, buf);
                    }
                    free(buf);
                    free(pktDescs);
                }

                /* Also probe magic cookie (codec-specific header data) */
                UInt32 cookieSize = 0;
                AudioFileGetPropertyInfo(audioFile,
                    kAudioFilePropertyMagicCookieData,
                    &cookieSize, NULL);
                if (cookieSize > 0 && cookieSize < 65536) {
                    void *cookie = malloc(cookieSize);
                    if (cookie) {
                        AudioFileGetProperty(audioFile,
                            kAudioFilePropertyMagicCookieData,
                            &cookieSize, cookie);
                        free(cookie);
                    }
                }
            }
            AudioFileClose(audioFile);
        }

        /*
         * Path 2: AudioFileStreamOpen (streaming parse path)
         * Exercises a completely different parser state machine
         */
        AudioFileStreamID stream = NULL;
        err = AudioFileStreamOpen(&fuzz, streamPropertyProc,
            streamPacketsProc, 0, &stream);
        if (err == noErr && stream) {
            /* Feed data in one shot - streaming parser handles chunking */
            UInt32 parseSize = (UInt32)(size < 65536 ? size : 65536);
            AudioFileStreamParseBytes(stream, parseSize, data, 0);
            AudioFileStreamClose(stream);
        }
    }
    return 0;
}
