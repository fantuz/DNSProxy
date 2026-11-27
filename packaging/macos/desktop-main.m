// Finder entry point for the shared GTK desktop. Resolve everything from the
// bundle so moving it, including Gatekeeper translocation, preserves its paths.
#import <AppKit/AppKit.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int launchError(NSString *detail) {
    fprintf(stderr, "DNSProxy: %s\n", detail.UTF8String);
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [NSApp activate];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"DNSProxy could not open the desktop monitor";
    alert.informativeText = detail;
    [alert runModal];
    return EXIT_FAILURE;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSBundle *bundle = NSBundle.mainBundle;
        NSURL *gui = [bundle.resourceURL URLByAppendingPathComponent:@"gui" isDirectory:YES];
        NSURL *launcher = [gui URLByAppendingPathComponent:@"dnsp-gui-macos"];
        NSURL *script = [gui URLByAppendingPathComponent:@"dnsp-gui.py"];
        NSURL *resolver = [bundle.bundleURL URLByAppendingPathComponent:@"Contents/Helpers/dnsp-modern"];

        // Use the same native Homebrew interpreter selection as the Terminal launcher.
        NSTask *probe = [[NSTask alloc] init];
        probe.executableURL = [NSURL fileURLWithPath:@"/bin/sh"];
        probe.arguments = @[launcher.path, @"--print-python"];
        NSPipe *pipe = [NSPipe pipe];
        probe.standardOutput = pipe;
        NSError *error = nil;
        if (![probe launchAndReturnError:&error]) return launchError(error.localizedDescription);
        NSData *output = [pipe.fileHandleForReading readDataToEndOfFile];
        [probe waitUntilExit];
        if (probe.terminationStatus != 0) {
            return launchError(@"Install the desktop runtime with Homebrew in Terminal:\n\nbrew install gtk4 pygobject3\n\nThen open DNSProxy again. The included Start-DNSProxy.command runs the resolver without Homebrew.");
        }
        NSString *python = [[[NSString alloc] initWithData:output encoding:NSUTF8StringEncoding]
            stringByTrimmingCharactersInSet:NSCharacterSet.newlineCharacterSet];
        if (!python.isAbsolutePath || ![NSFileManager.defaultManager isExecutableFileAtPath:python])
            return launchError(@"Could not locate an executable Homebrew Python for GTK.");

        // Keep the signed bundle read-only. exec preserves the Finder-launched PID.
        char **args = calloc((size_t)argc + 6, sizeof(*args));
        if (!args) return launchError(@"Insufficient memory to start the desktop monitor.");
        args[0] = (char *)python.fileSystemRepresentation;
        args[1] = "-B";
        args[2] = (char *)script.fileSystemRepresentation;
        args[3] = "--binary";
        args[4] = (char *)resolver.fileSystemRepresentation;
        size_t count = 5;
        for (int i = 1; i < argc; i++) {
            if (strncmp(argv[i], "-psn_", 5) != 0) args[count++] = argv[i];
        }
        execv(args[0], args);
        int saved = errno;
        free(args);
        return launchError([NSString stringWithFormat:@"Starting Python failed: %s", strerror(saved)]);
    }
}
