/**
 * validation_data.m — Generate Apple APNs validation data on macOS 13+ (Ventura or later)
 *
 * Uses the private AAAbsintheContext class from AppleAccount.framework to call
 * the underlying NAC (Network Attestation Credential) functions. No SIP modification,
 * no code injection, no jailbreak required.
 *
 * Protocol:
 *   1. Fetch validation cert from Apple (DER cert in a plist)
 *   2. NACInit: Pass cert to context → get session info request bytes
 *   3. Send request bytes to Apple's initializeValidation endpoint → get session info
 *   4. NACKeyEstablishment: Pass session info to context
 *   5. NACSign: Get final validation data bytes
 *
 * Build:
 *   cc -o validation_data validation_data.m -framework Foundation -fobjc-arc
 *
 * The output is the raw validation data bytes written to stdout (or a file),
 * suitable for use with rustpush's OSConfig::generate_validation_data().
 */

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ---- Configuration ----

static NSString *const kIDSBagURL = @"https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

// ---- Synchronous HTTP helper ----

static NSData *httpGet(NSString *urlStr, NSError **outError) {
    NSURL *url = [NSURL URLWithString:urlStr];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSData *result = nil;
    __block NSError *blockError = nil;

    NSURLSession *session = [NSURLSession sharedSession];
    [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        result = data;
        blockError = err;
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));

    if (blockError && outError) *outError = blockError;
    return result;
}

static NSData *httpPost(NSString *urlStr, NSData *body, NSString *contentType, NSInteger *outStatus, NSError **outError) {
    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPMethod:@"POST"];
    [req setHTTPBody:body];
    [req setValue:contentType forHTTPHeaderField:@"Content-Type"];
    [req setTimeoutInterval:30];

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSData *result = nil;
    __block NSError *blockError = nil;
    __block NSInteger status = 0;

    NSURLSession *session = [NSURLSession sharedSession];
    [[session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        result = data;
        blockError = err;
        if ([resp isKindOfClass:[NSHTTPURLResponse class]])
            status = [(NSHTTPURLResponse *)resp statusCode];
        dispatch_semaphore_signal(sem);
    }] resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC));

    if (outStatus) *outStatus = status;
    if (blockError && outError) *outError = blockError;
    return result;
}

// ---- IDS bag URL resolution ----

/**
 * Fetch and parse the IDS bag, returning the inner dictionary.
 * The bag endpoint returns a plist with a "bag" key containing a nested plist dictionary.
 */
static NSDictionary *fetchIDSBag(NSString *bagURL, NSError **outError) {
    NSError *fetchErr = nil;
    NSData *bagData = httpGet(bagURL, &fetchErr);
    if (!bagData) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:30
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Failed to fetch IDS bag: %@", fetchErr]}];
        return nil;
    }

    id outerPlist = [NSPropertyListSerialization propertyListWithData:bagData options:0 format:NULL error:&fetchErr];
    if (![outerPlist isKindOfClass:[NSDictionary class]] || !outerPlist[@"bag"]) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:31
            userInfo:@{NSLocalizedDescriptionKey: @"IDS bag response missing 'bag' key"}];
        return nil;
    }

    NSData *innerData = outerPlist[@"bag"];
    if (![innerData isKindOfClass:[NSData class]]) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:32
            userInfo:@{NSLocalizedDescriptionKey: @"IDS bag 'bag' value is not data"}];
        return nil;
    }

    id innerPlist = [NSPropertyListSerialization propertyListWithData:innerData options:0 format:NULL error:&fetchErr];
    if (![innerPlist isKindOfClass:[NSDictionary class]]) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:33
            userInfo:@{NSLocalizedDescriptionKey: @"IDS bag inner plist is not a dictionary"}];
        return nil;
    }

    return innerPlist;
}

// ---- NAC selector discovery ----

/**
 * Holds the three dynamically-discovered NAC selectors.
 */
typedef struct {
    SEL initSel;       // NACInit: cert → request bytes (returns @)
    SEL keyEstabSel;   // NACKeyEstablishment: sessionInfo → BOOL (returns B)
    SEL signSel;       // NACSign: nil → validation data (returns @)
} NACSelectors;

/**
 * Discover NAC selectors on AAAbsintheContext by type signature matching.
 *
 * Enumerates all instance methods, filters for the *:error: two-arg pattern,
 * and classifies by return type:
 *   - B or c (BOOL) return → NACKeyEstablishment (unique)
 *     ('B' = _Bool on ARM64, 'c' = signed char on x86_64)
 *   - @ (object) return → NACInit or NACSign (disambiguated by trial call)
 *
 * To distinguish init from sign: creates a temporary context and tries each
 * @-returning candidate with the cert data. NACInit returns non-nil request
 * bytes; NACSign on an uninitialized context returns nil.
 *
 * @param cls       The AAAbsintheContext class
 * @param certData  Certificate data (used for init/sign disambiguation)
 * @param out       Receives the discovered selectors
 * @param outError  Receives error info on failure
 * @return 0 on success, non-zero on failure
 */
static int discover_nac_selectors(Class cls, NSData *certData, NACSelectors *out, NSError **outError) {
    unsigned int methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    if (!methods) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:20
            userInfo:@{NSLocalizedDescriptionKey: @"class_copyMethodList returned NULL"}];
        return 20;
    }

    SEL boolSel = NULL;
    SEL objSels[2] = {NULL, NULL};
    int objCount = 0;

    for (unsigned int i = 0; i < methodCount; i++) {
        SEL sel = method_getName(methods[i]);
        const char *name = sel_getName(sel);
        const char *typeEnc = method_getTypeEncoding(methods[i]);

        if (!name || !typeEnc) continue;

        // Must end with ":error:" and have exactly 2 colons
        size_t len = strlen(name);
        if (len < 7) continue;
        if (strcmp(name + len - 7, ":error:") != 0) continue;

        int colons = 0;
        for (const char *p = name; *p; p++) {
            if (*p == ':') colons++;
        }
        if (colons != 2) continue;

        // Classify by return type (first char of type encoding)
        // BOOL is '_Bool' (encoding 'B') on ARM64, but 'signed char' (encoding 'c') on x86_64
        if (typeEnc[0] == 'B' || typeEnc[0] == 'c') {
            boolSel = sel;
        } else if (typeEnc[0] == '@') {
            if (objCount < 2) {
                objSels[objCount++] = sel;
            }
        }
    }
    free(methods);

    if (!boolSel) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:21
            userInfo:@{NSLocalizedDescriptionKey: @"No BOOL-returning (B or c) *:error: method found (NACKeyEstablishment)"}];
        return 21;
    }
    if (objCount != 2) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:22
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Expected 2 object-returning *:error: methods, found %d", objCount]}];
        return 22;
    }

    out->keyEstabSel = boolSel;

    // Disambiguate init vs sign: try each candidate on a throwaway context.
    // NACInit(cert) returns non-nil request bytes on a fresh context.
    // NACSign on an uninitialized context returns nil.
    id tempCtx = [[cls alloc] init];
    NSError *tempErr = nil;
    NSData *tryResult = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
        tempCtx, objSels[0], certData, &tempErr);

    if (tryResult != nil) {
        out->initSel = objSels[0];
        out->signSel = objSels[1];
    } else {
        out->initSel = objSels[1];
        out->signSel = objSels[0];
    }

    return 0;
}

// ---- Main validation data generation ----

/**
 * Generate APNs validation data.
 *
 * @param outData  On success, receives the validation data bytes (caller must free/release)
 * @param outError On failure, receives an error description
 * @return 0 on success, non-zero on failure
 */
int generate_validation_data(NSData **outData, NSError **outError) {
    // Load the AppleAccount framework (contains AAAbsintheContext)
    void *handle = dlopen("/System/Library/PrivateFrameworks/AppleAccount.framework/AppleAccount", RTLD_NOW);
    if (!handle) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"Failed to load AppleAccount.framework"}];
        return 1;
    }

    // --- Step 0: Resolve URLs from IDS bag ---
    NSError *fetchErr = nil;
    NSDictionary *bag = fetchIDSBag(kIDSBagURL, &fetchErr);
    if (!bag) {
        if (outError && !*outError) *outError = fetchErr;
        return 30;
    }
    NSString *certURL = bag[@"id-validation-cert"];
    NSString *initValidationURL = bag[@"id-initialize-validation"];
    if (!certURL || !initValidationURL) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:34
            userInfo:@{NSLocalizedDescriptionKey: @"IDS bag missing cert or validation URL"}];
        return 34;
    }

    // --- Step 1: Fetch validation certificate ---
    NSData *certPlistData = httpGet(certURL, &fetchErr);
    if (!certPlistData) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:2
            userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to fetch cert: %@", fetchErr]}];
        return 2;
    }

    id certPlist = [NSPropertyListSerialization propertyListWithData:certPlistData options:0 format:NULL error:&fetchErr];
    if (![certPlist isKindOfClass:[NSDictionary class]] || !certPlist[@"cert"]) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:3
            userInfo:@{NSLocalizedDescriptionKey: @"Invalid cert plist format"}];
        return 3;
    }
    NSData *certData = certPlist[@"cert"];

    // --- Step 2: NACInit — create context and get session info request ---
    Class ctxClass = NSClassFromString(@"AAAbsintheContext");
    if (!ctxClass) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:4
            userInfo:@{NSLocalizedDescriptionKey: @"AAAbsintheContext class not found"}];
        return 4;
    }

    // Discover NAC selectors by type signature (no hardcoded method names)
    NACSelectors sels = {0};
    int discoverResult = discover_nac_selectors(ctxClass, certData, &sels, outError);
    if (discoverResult != 0) return discoverResult;

    id ctx = [[ctxClass alloc] init];
    NSError *nacError = nil;

    // NACInit: cert → requestBytes (selector discovered at runtime)
    NSData *requestBytes = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
        ctx, sels.initSel, certData, &nacError);

    if (!requestBytes) {
        if (outError) *outError = nacError ?: [NSError errorWithDomain:@"NAC" code:5
            userInfo:@{NSLocalizedDescriptionKey: @"NACInit returned nil"}];
        return 5;
    }

    // --- Step 3: Send session info request to Apple ---
    NSDictionary *requestDict = @{@"session-info-request": requestBytes};
    NSData *requestPlist = [NSPropertyListSerialization dataWithPropertyList:requestDict
        format:NSPropertyListXMLFormat_v1_0 options:0 error:&nacError];

    NSInteger httpStatus = 0;
    NSData *responseData = httpPost(initValidationURL, requestPlist,
        @"application/x-apple-plist", &httpStatus, &nacError);

    if (httpStatus != 200 || !responseData) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:6
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"initializeValidation failed: HTTP %ld, %@", (long)httpStatus, nacError]}];
        return 6;
    }

    id responsePlist = [NSPropertyListSerialization propertyListWithData:responseData
        options:0 format:NULL error:&nacError];
    if (![responsePlist isKindOfClass:[NSDictionary class]]) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:7
            userInfo:@{NSLocalizedDescriptionKey: @"Invalid response plist"}];
        return 7;
    }

    NSNumber *status = responsePlist[@"status"];
    if (status && [status integerValue] != 0) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:8
            userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"Server returned status %@", status]}];
        return 8;
    }

    NSData *sessionInfo = responsePlist[@"session-info"];
    if (!sessionInfo) {
        if (outError) *outError = [NSError errorWithDomain:@"NAC" code:9
            userInfo:@{NSLocalizedDescriptionKey: @"No session-info in response"}];
        return 9;
    }

    // --- Step 4: NACKeyEstablishment — feed session info into context ---
    nacError = nil;
    // NACKeyEstablishment: sessionInfo → BOOL (selector discovered at runtime)
    BOOL keyResult = ((BOOL(*)(id, SEL, id, NSError **))objc_msgSend)(
        ctx, sels.keyEstabSel, sessionInfo, &nacError);

    if (!keyResult) {
        if (outError) *outError = nacError ?: [NSError errorWithDomain:@"NAC" code:10
            userInfo:@{NSLocalizedDescriptionKey: @"NACKeyEstablishment failed"}];
        return 10;
    }

    // --- Step 5: NACSign — get final validation data ---
    nacError = nil;
    // NACSign: nil → validationData (selector discovered at runtime)
    NSData *validationData = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
        ctx, sels.signSel, nil, &nacError);

    if (!validationData || ![validationData isKindOfClass:[NSData class]]) {
        if (outError) *outError = nacError ?: [NSError errorWithDomain:@"NAC" code:11
            userInfo:@{NSLocalizedDescriptionKey: @"NACSign failed or returned non-data"}];
        return 11;
    }

    *outData = validationData;
    return 0;
}

// ---- C FFI interface ----

/**
 * C-callable FFI function for generating validation data.
 *
 * @param out_buf      Receives a pointer to the validation data bytes (caller must free with free())
 * @param out_len      Receives the length of the validation data
 * @param out_err_buf  On error, receives a pointer to error message (caller must free with free())
 * @return 0 on success, non-zero on failure
 */
int nac_generate_validation_data(uint8_t **out_buf, size_t *out_len, char **out_err_buf) {
    @autoreleasepool {
        NSData *data = nil;
        NSError *error = nil;

        int result = generate_validation_data(&data, &error);

        if (result == 0 && data) {
            *out_len = [data length];
            *out_buf = (uint8_t *)malloc(*out_len);
            memcpy(*out_buf, [data bytes], *out_len);
            if (out_err_buf) *out_err_buf = NULL;
            return 0;
        } else {
            *out_buf = NULL;
            *out_len = 0;
            if (out_err_buf && error) {
                const char *msg = [[error localizedDescription] UTF8String];
                *out_err_buf = strdup(msg ? msg : "Unknown error");
            }
            return result;
        }
    }
}

// ============================================================================
// 3-step NAC API — exposes NACInit/NACKeyEstablishment/NACSign as individual
// C functions so callers can drive the HTTP session-info roundtrip themselves.
//
// This is what `rustpush::macos::MacOSConfig::generate_validation_data` needs:
// it owns the cert fetch and the id-initialize-validation POST, and expects
// a ValidationCtx that exposes new(cert) → request bytes, key_establishment,
// and sign() as distinct steps. The 3-step API lets `open-absinthe`'s
// ValidationCtx delegate each step directly to `AAAbsintheContext`, producing
// Local NAC validation data through upstream's existing HTTP flow — no
// patching of rustpush, no double-POST to Apple, no stub request bytes.
// ============================================================================

/**
 * Opaque handle that keeps an initialized `AAAbsintheContext` alive across
 * the three NAC steps. Stored as CFBridgingRetain to survive outside ARC.
 */
typedef struct {
    void *ctx;            // __bridge_retained AAAbsintheContext *
    SEL initSel;
    SEL keyEstabSel;
    SEL signSel;
} NacContext;

/**
 * Step 1: NACInit.
 * Loads AppleAccount.framework, creates AAAbsintheContext, discovers the
 * three NAC selectors, and calls NACInit(cert) to produce the session-info
 * request bytes. The caller POSTs those bytes to Apple's
 * id-initialize-validation endpoint.
 *
 * @param cert_buf         cert bytes (from id-validation-cert)
 * @param cert_len         length of cert_buf
 * @param out_handle       receives opaque context handle (free via nac_ctx_free)
 * @param out_request_buf  receives request bytes (caller must free())
 * @param out_request_len  receives length of request bytes
 * @param out_err_buf      receives error message on failure (caller must free())
 * @return 0 on success, non-zero on failure
 */
int nac_ctx_init(
    const uint8_t *cert_buf,
    size_t cert_len,
    void **out_handle,
    uint8_t **out_request_buf,
    size_t *out_request_len,
    char **out_err_buf
) {
    @autoreleasepool {
        if (out_handle) *out_handle = NULL;
        if (out_request_buf) *out_request_buf = NULL;
        if (out_request_len) *out_request_len = 0;
        if (out_err_buf) *out_err_buf = NULL;

        void *handle = dlopen("/System/Library/PrivateFrameworks/AppleAccount.framework/AppleAccount", RTLD_NOW);
        if (!handle) {
            if (out_err_buf) *out_err_buf = strdup("Failed to load AppleAccount.framework");
            return 1;
        }

        Class ctxClass = NSClassFromString(@"AAAbsintheContext");
        if (!ctxClass) {
            if (out_err_buf) *out_err_buf = strdup("AAAbsintheContext class not found");
            return 4;
        }

        NSData *certData = [NSData dataWithBytes:cert_buf length:cert_len];

        NACSelectors sels = {0};
        NSError *selErr = nil;
        int discoverResult = discover_nac_selectors(ctxClass, certData, &sels, &selErr);
        if (discoverResult != 0) {
            if (out_err_buf) {
                const char *msg = selErr ? [[selErr localizedDescription] UTF8String] : "selector discovery failed";
                *out_err_buf = strdup(msg ? msg : "selector discovery failed");
            }
            return discoverResult;
        }

        id ctx = [[ctxClass alloc] init];
        NSError *nacError = nil;
        NSData *requestBytes = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
            ctx, sels.initSel, certData, &nacError);

        if (!requestBytes) {
            if (out_err_buf) {
                const char *msg = nacError ? [[nacError localizedDescription] UTF8String] : "NACInit returned nil";
                *out_err_buf = strdup(msg ? msg : "NACInit returned nil");
            }
            return 5;
        }

        NacContext *nacCtx = (NacContext *)malloc(sizeof(NacContext));
        if (!nacCtx) {
            if (out_err_buf) *out_err_buf = strdup("Failed to allocate NacContext");
            return 40;
        }
        // Transfer ownership of ctx out of ARC so the context survives until nac_ctx_free.
        nacCtx->ctx = (void *)CFBridgingRetain(ctx);
        nacCtx->initSel = sels.initSel;
        nacCtx->keyEstabSel = sels.keyEstabSel;
        nacCtx->signSel = sels.signSel;

        NSUInteger reqLen = [requestBytes length];
        uint8_t *reqBuf = (uint8_t *)malloc(reqLen);
        if (!reqBuf) {
            CFBridgingRelease(nacCtx->ctx);
            free(nacCtx);
            if (out_err_buf) *out_err_buf = strdup("Failed to allocate request buffer");
            return 41;
        }
        memcpy(reqBuf, [requestBytes bytes], reqLen);

        *out_handle = (void *)nacCtx;
        *out_request_buf = reqBuf;
        *out_request_len = reqLen;
        return 0;
    }
}

/**
 * Step 2: NACKeyEstablishment.
 * Feeds Apple's session-info response into the AAAbsintheContext.
 */
int nac_ctx_key_establishment(
    void *handle,
    const uint8_t *session_info_buf,
    size_t session_info_len,
    char **out_err_buf
) {
    @autoreleasepool {
        if (out_err_buf) *out_err_buf = NULL;
        if (!handle) {
            if (out_err_buf) *out_err_buf = strdup("NULL NAC context handle");
            return 50;
        }
        NacContext *nacCtx = (NacContext *)handle;
        id ctx = (__bridge id)(nacCtx->ctx);
        NSData *sessionInfo = [NSData dataWithBytes:session_info_buf length:session_info_len];

        NSError *nacError = nil;
        BOOL keyResult = ((BOOL(*)(id, SEL, id, NSError **))objc_msgSend)(
            ctx, nacCtx->keyEstabSel, sessionInfo, &nacError);

        if (!keyResult) {
            if (out_err_buf) {
                const char *msg = nacError ? [[nacError localizedDescription] UTF8String] : "NACKeyEstablishment failed";
                *out_err_buf = strdup(msg ? msg : "NACKeyEstablishment failed");
            }
            return 10;
        }
        return 0;
    }
}

/**
 * Step 3: NACSign.
 * Produces the final validation data bytes from the established context.
 */
int nac_ctx_sign(
    void *handle,
    uint8_t **out_buf,
    size_t *out_len,
    char **out_err_buf
) {
    @autoreleasepool {
        if (out_buf) *out_buf = NULL;
        if (out_len) *out_len = 0;
        if (out_err_buf) *out_err_buf = NULL;

        if (!handle) {
            if (out_err_buf) *out_err_buf = strdup("NULL NAC context handle");
            return 50;
        }
        NacContext *nacCtx = (NacContext *)handle;
        id ctx = (__bridge id)(nacCtx->ctx);

        NSError *nacError = nil;
        NSData *validationData = ((id(*)(id, SEL, id, NSError **))objc_msgSend)(
            ctx, nacCtx->signSel, nil, &nacError);

        if (!validationData || ![validationData isKindOfClass:[NSData class]]) {
            if (out_err_buf) {
                const char *msg = nacError ? [[nacError localizedDescription] UTF8String] : "NACSign failed or returned non-data";
                *out_err_buf = strdup(msg ? msg : "NACSign failed or returned non-data");
            }
            return 11;
        }

        NSUInteger len = [validationData length];
        uint8_t *buf = (uint8_t *)malloc(len);
        if (!buf) {
            if (out_err_buf) *out_err_buf = strdup("Failed to allocate validation buffer");
            return 42;
        }
        memcpy(buf, [validationData bytes], len);
        *out_buf = buf;
        *out_len = len;
        return 0;
    }
}

/**
 * Release the NAC context handle. Safe to call with NULL.
 */
void nac_ctx_free(void *handle) {
    if (!handle) return;
    NacContext *nacCtx = (NacContext *)handle;
    if (nacCtx->ctx) {
        // CFBridgingRelease converts back to an ARC-managed reference; the
        // temporary then goes out of scope and the AAAbsintheContext dealloc
        // fires. The cast-to-void silences the unused-value warning.
        (void)CFBridgingRelease(nacCtx->ctx);
        nacCtx->ctx = NULL;
    }
    free(nacCtx);
}

// ---- CLI entry point (excluded when building as a library) ----

#ifndef NAC_NO_MAIN
int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL outputBase64 = NO;
        NSString *outputPath = nil;

        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--base64") == 0 || strcmp(argv[i], "-b") == 0) {
                outputBase64 = YES;
            } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                outputPath = [NSString stringWithUTF8String:argv[++i]];
            } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                fprintf(stderr, "Usage: %s [--base64|-b] [-o output_file]\n", argv[0]);
                fprintf(stderr, "  --base64  Output as base64 string (default: raw bytes)\n");
                fprintf(stderr, "  -o FILE   Write to file (default: stdout)\n");
                return 0;
            }
        }

        NSData *validationData = nil;
        NSError *error = nil;

        fprintf(stderr, "Generating APNs validation data...\n");
        int result = generate_validation_data(&validationData, &error);

        if (result != 0) {
            fprintf(stderr, "ERROR: %s\n", [[error localizedDescription] UTF8String]);
            return result;
        }

        fprintf(stderr, "Success: %lu bytes of validation data\n", (unsigned long)[validationData length]);

        if (outputPath) {
            if (outputBase64) {
                NSString *b64 = [validationData base64EncodedStringWithOptions:0];
                [b64 writeToFile:outputPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            } else {
                [validationData writeToFile:outputPath atomically:YES];
            }
            fprintf(stderr, "Written to %s\n", [outputPath UTF8String]);
        } else {
            if (outputBase64) {
                NSString *b64 = [validationData base64EncodedStringWithOptions:0];
                printf("%s\n", [b64 UTF8String]);
            } else {
                fwrite([validationData bytes], 1, [validationData length], stdout);
            }
        }

        return 0;
    }
}

#endif // NAC_NO_MAIN
