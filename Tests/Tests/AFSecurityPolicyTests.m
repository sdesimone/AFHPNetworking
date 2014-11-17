// AFHPSecurityPolicyTests.m
//
// Copyright (c) 2013-2014 AFHPNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFTestCase.h"

#import "AFSecurityPolicy.h"

@interface AFHPSecurityPolicyTests : AFHPTestCase
@end

static SecTrustRef AFHPUTTrustChainForCertsInDirectory(NSString *directoryPath) {
    NSArray *certFileNames = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directoryPath error:nil];
    NSMutableArray *certs  = [NSMutableArray arrayWithCapacity:[certFileNames count]];
    for (NSString *path in certFileNames) {
        NSData *certData = [NSData dataWithContentsOfFile:[directoryPath stringByAppendingPathComponent:path]];
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
        [certs addObject:(__bridge id)(cert)];
    }

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    SecTrustCreateWithCertificates((__bridge CFTypeRef)(certs), policy, &trust);
    CFRelease(policy);

    return trust;
}

static SecTrustRef AFHPUTHTTPBinOrgServerTrust() {
    NSString *bundlePath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] resourcePath];
    NSString *serverCertDirectoryPath = [bundlePath stringByAppendingPathComponent:@"HTTPBinOrgServerTrustChain"];

    return AFHPUTTrustChainForCertsInDirectory(serverCertDirectoryPath);
}

static SecTrustRef AFHPUTADNNetServerTrust() {
    NSString *bundlePath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] resourcePath];
    NSString *serverCertDirectoryPath = [bundlePath stringByAppendingPathComponent:@"ADNNetServerTrustChain"];

    return AFHPUTTrustChainForCertsInDirectory(serverCertDirectoryPath);
}

static SecCertificateRef AFHPUTHTTPBinOrgCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"httpbinorg_11212014" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFHPUTGeotrustRootCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"Geotrust_Root_CA" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];
    
    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFHPUTRapidSSLCertificate() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"Rapid_SSL_CA" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];
    
    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFHPUTSelfSignedCertificateWithoutDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"NoDomains" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFHPUTSelfSignedCertificateWithCommonNameDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"foobar.com" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static SecCertificateRef AFHPUTSelfSignedCertificateWithDNSNameDomain() {
    NSString *certPath = [[NSBundle bundleForClass:[AFHPSecurityPolicyTests class]] pathForResource:@"AltName" ofType:@"cer"];
    NSCAssert(certPath != nil, @"Path for certificate should not be nil");
    NSData *certData = [NSData dataWithContentsOfFile:certPath];

    return SecCertificateCreateWithData(NULL, (__bridge CFDataRef)(certData));
}

static NSArray * AFHPCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }
    
    return [NSArray arrayWithArray:trustChain];
}

static SecTrustRef AFHPUTTrustWithCertificate(SecCertificateRef certificate) {
    NSArray *certs  = [NSArray arrayWithObject:(__bridge id)(certificate)];

    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    SecTrustCreateWithCertificates((__bridge CFTypeRef)(certs), policy, &trust);
    CFRelease(policy);

    return trust;
}

#pragma mark -

@implementation AFHPSecurityPolicyTests

- (void)testLeafPublicKeyPinningIsEnforcedForHTTPBinOrgPinnedCertificateAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];

    SecCertificateRef geotrustRootCertificate = AFHPUTGeotrustRootCertificate();
    SecCertificateRef rapidSSLCertificate = AFHPUTRapidSSLCertificate();
    SecCertificateRef httpBinCertificate = AFHPUTHTTPBinOrgCertificate();
    
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(geotrustRootCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(rapidSSLCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate)]];
    
    CFRelease(geotrustRootCertificate);
    CFRelease(rapidSSLCertificate);
    CFRelease(httpBinCertificate);
    
    [policy setValidatesCertificateChain:NO];
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testPublicKeyChainPinningIsEnforcedForHTTPBinOrgPinnedCertificateAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];

    SecTrustRef clientTrust = AFHPUTHTTPBinOrgServerTrust();
    NSArray * certificates = AFHPCertificateTrustChainForServerTrust(clientTrust);
    CFRelease(clientTrust);
    [policy setPinnedCertificates:certificates];

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testLeafCertificatePinningIsEnforcedForHTTPBinOrgPinnedCertificateAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];

    SecCertificateRef geotrustRootCertificate = AFHPUTGeotrustRootCertificate();
    SecCertificateRef rapidSSLCertificate = AFHPUTRapidSSLCertificate();
    SecCertificateRef httpBinCertificate = AFHPUTHTTPBinOrgCertificate();
    
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(geotrustRootCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(rapidSSLCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate)]];
    
    CFRelease(geotrustRootCertificate);
    CFRelease(rapidSSLCertificate);
    CFRelease(httpBinCertificate);
    
    [policy setValidatesCertificateChain:NO];
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testCertificateChainPinningIsEnforcedForHTTPBinOrgPinnedCertificateAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    SecTrustRef clientTrust = AFHPUTHTTPBinOrgServerTrust();
    NSArray * certificates = AFHPCertificateTrustChainForServerTrust(clientTrust);
    CFRelease(clientTrust);
    [policy setPinnedCertificates:certificates];

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testNoPinningIsEnforcedForHTTPBinOrgPinnedCertificateAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeNone];

    SecCertificateRef certificate = AFHPUTHTTPBinOrgCertificate();
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    CFRelease(certificate);
    [policy setAllowInvalidCertificates:YES];

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Pinning should not have been enforced");
    CFRelease(trust);
}

- (void)testPublicKeyPinningFailsForHTTPBinOrgIfNoCertificateIsPinned {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    [policy setPinnedCertificates:@[]];

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"] == NO, @"HTTPBin.org Public Key Pinning Should have failed with no pinned certificate");
    CFRelease(trust);
}

- (void)testCertificatePinningIsEnforcedForHTTPBinOrgPinnedCertificateWithDomainNameValidationAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    
    SecCertificateRef geotrustRootCertificate = AFHPUTGeotrustRootCertificate();
    SecCertificateRef rapidSSLCertificate = AFHPUTRapidSSLCertificate();
    SecCertificateRef httpBinCertificate = AFHPUTHTTPBinOrgCertificate();
    
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(geotrustRootCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(rapidSSLCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate)]];
    
    CFRelease(geotrustRootCertificate);
    CFRelease(rapidSSLCertificate);
    CFRelease(httpBinCertificate);
    
    policy.validatesDomainName = YES;
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testCertificatePinningIsEnforcedForHTTPBinOrgPinnedCertificateWithCaseInsensitiveDomainNameValidationAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    
    SecCertificateRef geotrustRootCertificate = AFHPUTGeotrustRootCertificate();
    SecCertificateRef rapidSSLCertificate = AFHPUTRapidSSLCertificate();
    SecCertificateRef httpBinCertificate = AFHPUTHTTPBinOrgCertificate();
    
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(geotrustRootCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(rapidSSLCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate)]];
    
    CFRelease(geotrustRootCertificate);
    CFRelease(rapidSSLCertificate);
    CFRelease(httpBinCertificate);
    
    policy.validatesDomainName = YES;

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testCertificatePinningIsEnforcedForHTTPBinOrgPinnedPublicKeyWithDomainNameValidationAgainstHTTPBinOrgServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    
    SecCertificateRef geotrustRootCertificate = AFHPUTGeotrustRootCertificate();
    SecCertificateRef rapidSSLCertificate = AFHPUTRapidSSLCertificate();
    SecCertificateRef httpBinCertificate = AFHPUTHTTPBinOrgCertificate();
    
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(geotrustRootCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(rapidSSLCertificate),
                                    (__bridge_transfer NSData *)SecCertificateCopyData(httpBinCertificate)]];
    
    CFRelease(geotrustRootCertificate);
    CFRelease(rapidSSLCertificate);
    CFRelease(httpBinCertificate);
    
    policy.validatesDomainName = YES;
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Public Key Pinning Mode Failed");
    CFRelease(trust);
}

- (void)testCertificatePinningFailsForHTTPBinOrgIfNoCertificateIsPinned {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    [policy setPinnedCertificates:@[]];
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"] == NO, @"HTTPBin.org Certificate Pinning Should have failed with no pinned certificate");
    CFRelease(trust);
}

- (void)testCertificatePinningFailsForHTTPBinOrgIfDomainNameDoesntMatch {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    SecCertificateRef certificate = AFHPUTHTTPBinOrgCertificate();
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    CFRelease(certificate);
    policy.validatesDomainName = YES;
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"www.httpbin.org"] == NO, @"HTTPBin.org Certificate Pinning Should have failed with no pinned certificate");
    CFRelease(trust);
}

- (void)testNoPinningIsEnforcedForHTTPBinOrgIfNoCertificateIsPinned {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeNone];
    [policy setPinnedCertificates:@[]];

    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"], @"HTTPBin.org Pinning should not have been enforced");
    CFRelease(trust);
}

- (void)testPublicKeyPinningForHTTPBinOrgFailsWhenPinnedAgainstADNServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    SecCertificateRef certificate = AFHPUTHTTPBinOrgCertificate();
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    [policy setValidatesCertificateChain:NO];

    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"] == NO, @"HTTPBin.org Public Key Pinning Should have failed against ADN");
    CFRelease(trust);
}

- (void)testCertificatePinningForHTTPBinOrgFailsWhenPinnedAgainstADNServerTrust {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    SecCertificateRef certificate = AFHPUTHTTPBinOrgCertificate();
    [policy setPinnedCertificates:@[(__bridge_transfer NSData *)SecCertificateCopyData(certificate)]];
    [policy setValidatesCertificateChain:NO];

    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"httpbin.org"] == NO, @"HTTPBin.org Certificate Pinning Should have failed against ADN");
    CFRelease(trust);
}

- (void)testDefaultPolicyContainsHTTPBinOrgCertificate {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy defaultPolicy];
    SecCertificateRef cert = AFHPUTHTTPBinOrgCertificate();
    NSData *certData = (__bridge NSData *)(SecCertificateCopyData(cert));
    CFRelease(cert);
    NSInteger index = [policy.pinnedCertificates indexOfObjectPassingTest:^BOOL(NSData *data, NSUInteger idx, BOOL *stop) {
        return [data isEqualToData:certData];
    }];

    XCTAssert(index!=NSNotFound, @"HTTPBin.org certificate not found in the default certificates");
}

- (void)testCertificatePinningIsEnforcedWhenPinningSelfSignedCertificateWithoutDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithoutDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    policy.validatesDomainName = NO;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foo.bar"], @"Certificate should be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testCertificatePinningWhenPinningSelfSignedCertificateWithoutDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithoutDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foo.bar"] == NO, @"Certificate should not be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testCertificatePinningIsEnforcedWhenPinningSelfSignedCertificateWithCommonNameDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithCommonNameDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Certificate should be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testCertificatePinningWhenPinningSelfSignedCertificateWithCommonNameDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithCommonNameDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foo.bar"] == NO, @"Certificate should not be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testCertificatePinningIsEnforcedWhenPinningSelfSignedCertificateWithDNSNameDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foobar.com"], @"Certificate should be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testCertificatePinningWhenPinningSelfSignedCertificateWithDNSNameDomain {
    SecCertificateRef certificate = AFHPUTSelfSignedCertificateWithDNSNameDomain();
    SecTrustRef trust = AFHPUTTrustWithCertificate(certificate);

    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    policy.pinnedCertificates = @[ (__bridge_transfer id)SecCertificateCopyData(certificate) ];
    policy.allowInvalidCertificates = YES;
    XCTAssert([policy evaluateServerTrust:trust forDomain:@"foo.bar"] == NO, @"Certificate should not be trusted");

    CFRelease(trust);
    CFRelease(certificate);
}

- (void)testDefaultPolicySetToCertificateChain {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"Pinning with Default Certficiate Chain Failed");
    CFRelease(trust);
}

- (void)testDefaultPolicySetToLeafCertificate {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    [policy setValidatesCertificateChain:NO];
    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"Pinning with Default Leaf Certficiate Failed");
    CFRelease(trust);
}

- (void)testDefaultPolicySetToPublicKeyChain {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"Pinning with Default Public Key Chain Failed");
    CFRelease(trust);
}

- (void)testDefaultPolicySetToLeafPublicKey {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    [policy setValidatesCertificateChain:NO];
    SecTrustRef trust = AFHPUTADNNetServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil], @"Pinning with Default Leaf Public Key Failed");
    CFRelease(trust);
}

- (void)testDefaultPolicySetToCertificateChainFailsWithMissingChain {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeCertificate];
    
    // By default the cer files are picked up from the bundle, this forces them to be cleared to emulate having none available
    [policy setPinnedCertificates:@[]];
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil] == NO, @"Pinning with Certificate Chain Mode and Missing Chain should have failed");
    CFRelease(trust);
}

- (void)testDefaultPolicySetToPublicKeyChainFailsWithMissingChain {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    
    // By default the cer files are picked up from the bundle, this forces them to be cleared to emulate having none available
    [policy setPinnedCertificates:@[]];
    
    SecTrustRef trust = AFHPUTHTTPBinOrgServerTrust();
    XCTAssert([policy evaluateServerTrust:trust forDomain:nil] == NO, @"Pinning with Public Key Chain Mode and Missing Chain should have failed");
    CFRelease(trust);
}

- (void)testDefaultPolicyIsSetToAFSSLPinningModePublicKey {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy defaultPolicy];

    XCTAssert(policy.SSLPinningMode==AFSSLPinningModeNone, @"Default policy is not set to AFHPSSLPinningModePublicKey.");
}

- (void)testDefaultPolicyIsSetToNotAllowInvalidSSLCertificates {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy defaultPolicy];

    XCTAssert(policy.allowInvalidCertificates == NO, @"Default policy should not allow invalid ssl certificates");
}

- (void)testPolicyWithPinningModeIsSetToNotAllowInvalidSSLCertificates {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeNone];
    
    XCTAssert(policy.allowInvalidCertificates == NO, @"policyWithPinningMode: should not allow invalid ssl certificates by default.");
}

- (void)testPolicyWithPinningModeIsSetToValidatesDomainName {
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModeNone];
    
    XCTAssert(policy.validatesDomainName == NO, @"policyWithPinningMode: should not allow invalid ssl certificates by default.");
}

- (void)testThatSSLPinningPolicyClassMethodContainsDefaultCertificates{
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy policyWithPinningMode:AFHPSSLPinningModePublicKey];
    [policy setValidatesCertificateChain:NO];
    XCTAssertNotNil(policy.pinnedCertificates, @"Default certificate array should not be empty for SSL pinning mode policy");
}

- (void)testThatDefaultPinningPolicyClassMethodContainsNoDefaultCertificates{
    AFHPSecurityPolicy *policy = [AFHPSecurityPolicy defaultPolicy];
    XCTAssertNil(policy.pinnedCertificates, @"Default certificate array should be empty for default policy.");
}

@end
