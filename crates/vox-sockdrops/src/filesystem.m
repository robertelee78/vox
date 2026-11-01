#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>

static void vox_error(NSError *error, char *buffer, size_t capacity) {
    if (capacity == 0) return;
    NSMutableString *text = [NSMutableString string];
    NSError *cause = error;
    for (unsigned depth = 0; cause && depth < 8; ++depth) {
        if (depth) [text appendString:@"; caused by "];
        [text appendFormat:@"%@ code %ld: %@", cause.domain, (long)cause.code,
                           cause.localizedDescription];
        id next = cause.userInfo[NSUnderlyingErrorKey];
        cause = [next isKindOfClass:[NSError class]] ? next : nil;
    }
    if (!error) [text appendString:@"Foundation returned no error"];
    snprintf(buffer, capacity, "%s", text.UTF8String ?: "error description unavailable");
}

int vox_replacement_directory(const char *path, char *result, size_t result_capacity,
                              char *error_buffer, size_t error_capacity) {
    @autoreleasepool {
        NSURL *url = [NSURL fileURLWithFileSystemRepresentation:path isDirectory:YES relativeToURL:nil];
        NSError *error = nil;
        NSURL *replacement = [[NSFileManager defaultManager]
            URLForDirectory:NSItemReplacementDirectory inDomain:NSUserDomainMask
            appropriateForURL:url create:YES error:&error];
        if (!replacement) { vox_error(error, error_buffer, error_capacity); return 0; }
        const char *bytes = replacement.fileSystemRepresentation;
        if (!bytes || strlen(bytes) >= result_capacity) {
            if (error_capacity) snprintf(error_buffer, error_capacity, "replacement path exceeds buffer");
            return 0;
        }
        memcpy(result, bytes, strlen(bytes) + 1);
        return 1;
    }
}

int vox_remove_item(const char *path, char *error_buffer, size_t error_capacity) {
    @autoreleasepool {
        NSURL *url = [NSURL fileURLWithFileSystemRepresentation:path isDirectory:YES relativeToURL:nil];
        NSError *error = nil;
        if (![[NSFileManager defaultManager] removeItemAtURL:url error:&error]) {
            vox_error(error, error_buffer, error_capacity);
            return 0;
        }
        return 1;
    }
}
