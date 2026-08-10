//
//  FilzaPadlockBypass.h
//  W0lfSword
//
//  Header for Filza UI padlock bypass hooks
//

#ifndef FilzaPadlockBypass_h
#define FilzaPadlockBypass_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// Initialize padlock bypass hooks - call this in %ctor
void initFilzaPadlockBypass(void);

// Permission check helpers
BOOL filza_canEditPath(NSString *path);
BOOL filza_canWritePath(NSString *path);
BOOL filza_canDeletePath(NSString *path);
BOOL filza_canCreatePath(NSString *path);

#endif
