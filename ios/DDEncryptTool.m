//
//  DDEncryptTool.m
//  testProject
//
//  Created by garin on 16/5/23.
//  Copyright © 2016年 garin. All rights reserved.
//

#import "DDEncryptTool.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#define kChosenCipherBlockSize	kCCBlockSizeAES128
#define kChosenCipherKeySize	kCCKeySizeAES128

@implementation DDEncryptTool

CCOptions padding = kCCOptionPKCS7Padding;

+ (NSString *) encryptString:(NSString *)plainSourceStringToEncrypt
                       byKey:(NSString *)customKey {
    NSData *_secretData = [plainSourceStringToEncrypt dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptedData = [self encrypt:_secretData key:[customKey dataUsingEncoding:NSUTF8StringEncoding] padding:&padding];

    NSString *base64String = [encryptedData base64EncodedStringWithOptions:0];
    
    return base64String;
}

+ (NSString *) decryptString:(NSString *)base64StringToDecrypt
                       byKey:(NSString *)cutomKey {
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64StringToDecrypt options:0];
    
    NSData *data = [self decrypt:decodedData
                               key:[cutomKey dataUsingEncoding:NSUTF8StringEncoding]
                           padding: &padding];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}



#pragma mark -- 

+ (NSData *)encrypt:(NSData *)plainText
                key:(NSData *)aSymmetricKey
            padding:(CCOptions *)pkcs7 {
    return [self doCipher:plainText key:aSymmetricKey context:kCCEncrypt padding:pkcs7];
}

+ (NSData *)decrypt:(NSData *)plainText
                key:(NSData *)aSymmetricKey
            padding:(CCOptions *)pkcs7 {
    return [self doCipher:plainText key:aSymmetricKey context:kCCDecrypt padding:pkcs7];
}

+ (NSData *)doCipher:(NSData *)plainText
                 key:(NSData *)aSymmetricKey
             context:(CCOperation)encryptOrDecrypt
             padding:(CCOptions *)pkcs7 {
    CCCryptorStatus ccStatus = kCCSuccess;
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    // A friendly helper pointer.
    uint8_t * ptr;
    
    // Initialization vector; dummy in this case 0's.
    uint8_t iv[kChosenCipherBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
    
    plainTextBufferSize = [plainText length];
    
    // Create and Initialize the crypto reference.
    ccStatus = CCCryptorCreate(encryptOrDecrypt,
                               kCCAlgorithmAES128,
                               *pkcs7,
                               (const void *)[aSymmetricKey bytes],
                               kChosenCipherKeySize,
                               (const void *)iv,
                               &thisEncipher
                               );
    
    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);
    
    // Allocate buffer.
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t) );
    
    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    // Initialize some necessary book keeping.
    
    ptr = bufferPtr;
    
    // Set up initial size.
    remainingBytes = bufferPtrSize;
    
    // Actually perform the encryption or decryption.
    ccStatus = CCCryptorUpdate(thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );
    
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
    
    ccStatus = CCCryptorFinal(thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );
    
    totalBytesWritten += movedBytes;
    
    if(thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }
    
    if (ccStatus == kCCSuccess)
        cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    else
        cipherOrPlainText = nil;
    
    if(bufferPtr) free(bufferPtr);
    
    return cipherOrPlainText;
}


@end
