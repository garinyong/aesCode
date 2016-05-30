//
//  DDEncryptTool.h
//  testProject
//
//  Created by garin on 16/5/23.
//  Copyright © 2016年 garin. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DDEncryptTool : NSObject

+ (NSString *) encryptString:(NSString *)plainSourceStringToEncrypt
                       byKey:(NSString *)customKey;


+ (NSString *) decryptString:(NSString *)base64StringToDecrypt
                       byKey:(NSString *)cutomKey;

@end
