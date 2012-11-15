
#import <Security/Security.h>
#import "BoxSecurity.h"

@implementation BoxSecurity

static NSString *serviceName = @"com.box.boxSDK";

+ (NSMutableDictionary *)searchDictionary:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [[NSMutableDictionary alloc] init];  
	
    [searchDictionary setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
	
    NSData *encodedIdentifier = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    [searchDictionary setObject:encodedIdentifier forKey:(id)kSecAttrGeneric];
    [searchDictionary setObject:encodedIdentifier forKey:(id)kSecAttrAccount];
    [searchDictionary setObject:serviceName forKey:(id)kSecAttrService];
	
    return [searchDictionary autorelease]; 
}

+ (NSString *)searchKeychainMatching:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [BoxSecurity searchDictionary:identifier];
	
    // Add search attributes
    [searchDictionary setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
	
    // Add search return types
    [searchDictionary setObject:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
	
    NSData *result = nil;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef)searchDictionary,
                                          (CFTypeRef *)&result);
    
    NSString * returnValue = nil;
    if (status == errSecSuccess) {
        returnValue = [[[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding] autorelease];
    }
    [result release];
    return returnValue;
}

+ (BOOL)createKeychainValue:(NSString *)password forIdentifier:(NSString *)identifier {
    NSMutableDictionary *dictionary = [BoxSecurity searchDictionary:identifier];
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    
    [dictionary setObject:passwordData forKey:(id)kSecValueData];
	
    OSStatus status = SecItemAdd((CFDictionaryRef)dictionary, NULL);
	
    if (status == errSecSuccess) {
        return YES;
    }
    return NO;
}

+ (BOOL)updateKeychainValue:(NSString *)password forIdentifier:(NSString *)identifier {
    
    NSMutableDictionary *searchDictionary = [BoxSecurity searchDictionary:identifier];
    NSMutableDictionary *updateDictionary = [[NSMutableDictionary alloc] init];
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    [updateDictionary setObject:passwordData forKey:(id)kSecValueData];
	
    OSStatus status = SecItemUpdate((CFDictionaryRef)searchDictionary,
                                    (CFDictionaryRef)updateDictionary);
    
    [updateDictionary release];
	
    if (status == errSecSuccess) {
        return YES;
    }
    return NO;
}

+ (void)deleteKeychainValue:(NSString *)identifier {
	
    NSMutableDictionary *searchDictionary = [BoxSecurity searchDictionary:identifier];
    SecItemDelete((CFDictionaryRef)searchDictionary);
}

@end

