//
//  MyDocument.m
//  PythonLauncher
//
//  Created by Jack Jansen on Fri Jul 19 2002.
//  Copyright (c) 2002 __MyCompanyName__. All rights reserved.
//

#import "MyDocument.h"
#import "MyAppDelegate.h"

@implementation MyDocument

- (id)init
{
    [super init];
    if (self) {
    
        // Add your subclass-specific initialization here.
        // If an error occurs here, send a [self dealloc] message and return nil.
        script = @"<no script>.py";
        filetype = @"Python Script";    
    }
    return self;
}

- (NSString *)windowNibName
{
    // Override returning the nib file name of the document
    // If you need to use a subclass of NSWindowController or if your document supports multiple NSWindowControllers, you should remove this method and override -makeWindowControllers instead.
    return @"MyDocument";
}

- (void)close
{
    NSApplication *app = [NSApplication sharedApplication];
    [super close];
    if ([[app delegate] shouldTerminate])
        [app terminate: self];
}

- (void)load_defaults
{
    settings = [FileSettings newSettingsForFileType: filetype];
}

- (void)update_display
{
//    [[self window] setTitle: script];
    
    [interpreter setStringValue: [settings interpreter]];
    [debug setState: [settings debug]];
    [verbose setState: [settings verbose]];
    [inspect setState: [settings inspect]];
    [optimize setState: [settings optimize]];
    [nosite setState: [settings nosite]];
    [tabs setState: [settings tabs]];
    [others setStringValue: [settings others]];
    [with_terminal setState: [settings with_terminal]];
    
    [commandline setStringValue: [settings commandLineForScript: script]];
}

- (void)update_settings
{
    [settings updateFromSource: self];
}

- (BOOL)run
{
    const char *cmdline;
    int sts;
    
    if ([settings with_terminal]) {
        NSLog(@"Terminal not implemented yet\n");
        return NO;
    }
    cmdline = [[settings commandLineForScript: script] cString];
    sts = system(cmdline);
    if (sts) {
        NSLog(@"Exit status: %d\n", sts);
        return NO;
    }
    return YES;
}

- (void)windowControllerDidLoadNib:(NSWindowController *) aController
{
    [super windowControllerDidLoadNib:aController];
    // Add any code here that need to be executed once the windowController has loaded the document's window.
    [self load_defaults];
    [self update_display];
}

- (NSData *)dataRepresentationOfType:(NSString *)aType
{
    // Insert code here to write your document from the given data.  You can also choose to override -fileWrapperRepresentationOfType: or -writeToFile:ofType: instead.
    return nil;
}

- (BOOL)readFromFile:(NSString *)fileName ofType:(NSString *)type;
{
    // Insert code here to read your document from the given data.  You can also choose to override -loadFileWrapperRepresentation:ofType: or -readFromFile:ofType: instead.
    BOOL show_ui;
    
    // ask the app delegate whether we should show the UI or not. 
    show_ui = [[[NSApplication sharedApplication] delegate] shouldShowUI];
    script = [fileName retain];
    filetype = [type retain];
    settings = [FileSettings newSettingsForFileType: filetype];
    if (show_ui) {
        [self update_display];
        return YES;
    } else {
        [self run];
        [self close];
        return NO;
    }
}

- (IBAction)do_run:(id)sender
{
    [self update_settings];
    [self update_display];
    if ([self run])
        [self close];
}

- (IBAction)do_cancel:(id)sender
{
    [self close];
}


- (IBAction)do_reset:(id)sender
{
    [self load_defaults];
    [self update_display];
}

- (IBAction)do_apply:(id)sender
{
    [self update_settings];
    [self update_display];
}

// FileSettingsSource protocol 
- (NSString *) interpreter { return [interpreter stringValue];};
- (BOOL) debug { return [debug state];};
- (BOOL) verbose { return [verbose state];};
- (BOOL) inspect { return [inspect state];};
- (BOOL) optimize { return [optimize state];};
- (BOOL) nosite { return [nosite state];};
- (BOOL) tabs { return [tabs state];};
- (NSString *) others { return [others stringValue];};
- (BOOL) with_terminal { return [with_terminal state];};

// Delegates
- (void)controlTextDidChange:(NSNotification *)aNotification
{
    [self update_settings];
    [self update_display];
};

@end
