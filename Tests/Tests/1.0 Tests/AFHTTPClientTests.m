// AFHPHTTPClientTests.m
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

#import "AFNetworkingTests.h"

@interface AFHPHTTPClientTests : SenTestCase
@property (readwrite, nonatomic, strong) AFHPHTTPSessionManager *client;
@end

@implementation AFHPHTTPClientTests

- (void)setUp {
    self.client = [AFHPHTTPSessionManager clientWithBaseURL:[NSURL URLWithString:AFHPNetworkingTestsBaseURLString]];
}

#pragma mark -

- (void)testInitRaisesException {
    expect(^{ (void)[[AFHPHTTPSessionManager alloc] init]; }).to.raiseAny();
}

- (void)testDefaultHeaders {
    [self.client setDefaultHeader:@"x-some-key" value:@"SomeValue"];
    expect([self.client defaultValueForHeader:@"x-some-key"]).to.equal(@"SomeValue");

    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    expect([request valueForHTTPHeaderField:@"x-some-key"]).to.equal(@"SomeValue");

    expect(^{ [self.client setDefaultHeader:@"x-some-key" value:nil]; }).toNot.raise(nil);
}

- (void)testReachabilityStatus {
    [Expecta setAsynchronousTestTimeout:5.0];

    expect(self.client.networkReachabilityStatus).to.equal(@(AFHPNetworkReachabilityStatusUnknown));

    __block AFHPNetworkReachabilityStatus reachabilityStatus = self.client.networkReachabilityStatus;

    [self.client setReachabilityStatusChangeBlock:^(AFHPNetworkReachabilityStatus status) {
        reachabilityStatus = status;
    }];

    expect(reachabilityStatus).will.equal(@(AFHPNetworkReachabilityStatusReachableViaWiFi));
}

- (void)testJSONRequestOperationContruction {
    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    expect([AFHPJSONRequestOperation canProcessRequest:request]).to.beTruthy();

    AFHPHTTPRequestOperation *operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPHTTPRequestOperation class]);

    [self.client registerHTTPOperationClass:[AFHPJSONRequestOperation class]];
    operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPJSONRequestOperation class]);

    [self.client unregisterHTTPOperationClass:[AFHPJSONRequestOperation class]];
    operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPHTTPRequestOperation class]);
}

- (void)testXMLRequestOperationContruction {
    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    [request setValue:@"application/xml" forHTTPHeaderField:@"Accept"];

    expect([AFHPXMLRequestOperation canProcessRequest:request]).to.beTruthy();

    AFHPHTTPRequestOperation *operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPHTTPRequestOperation class]);

    [self.client registerHTTPOperationClass:[AFHPXMLRequestOperation class]];
    operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPXMLRequestOperation class]);
}

- (void)testImageRequestOperationContruction {
    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    [request setValue:@"image/png" forHTTPHeaderField:@"Accept"];

    expect([AFHPImageRequestOperation canProcessRequest:request]).to.beTruthy();

    AFHPHTTPRequestOperation *operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPHTTPRequestOperation class]);

    [self.client registerHTTPOperationClass:[AFHPImageRequestOperation class]];
    operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect([operation class]).to.equal([AFHPImageRequestOperation class]);
}

- (void)testThatEnqueueBatchOfHTTPRequestOperationsFiresCompletionBlockAfterEveryRequestCompleted {
    [Expecta setAsynchronousTestTimeout:5.0];

    __block NSDate *firstCallbackTime = nil;
    __block NSDate *secondCallbackTime = nil;
    __block NSDate *batchCallbackTime = nil;

    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/" parameters:nil];
    AFHPHTTPRequestOperation *firstOperation = [self.client HTTPRequestOperationWithRequest:request success:^(AFHPHTTPRequestOperation *operation, id responseObject) {
        firstCallbackTime = [NSDate date];
    } failure:^(AFHPHTTPRequestOperation *operation, NSError *error) {
        firstCallbackTime = [NSDate date];
    }];

    AFHPHTTPRequestOperation *secondOperation = [self.client HTTPRequestOperationWithRequest:request success:^(AFHPHTTPRequestOperation *operation, id responseObject) {
        secondCallbackTime = [NSDate date];
    } failure:^(AFHPHTTPRequestOperation *operation, NSError *error) {
        secondCallbackTime = [NSDate date];
    }];

    [self.client enqueueBatchOfHTTPRequestOperations:@[ firstOperation, secondOperation ] progressBlock:nil completionBlock:^(NSArray *operations) {
        batchCallbackTime = [NSDate date];
    }];

    expect(self.client.operationQueue.operationCount).will.equal(0);
    expect(firstCallbackTime).willNot.beNil();
    expect(secondCallbackTime).willNot.beNil();
    expect(batchCallbackTime).willNot.beNil();
    expect(batchCallbackTime).beGreaterThan(firstCallbackTime);
    expect(batchCallbackTime).beGreaterThan(secondCallbackTime);
}

- (void)testAuthorizationHeaderWithInvalidUsernamePassword {
    [Expecta setAsynchronousTestTimeout:5.0];

    __block NSHTTPURLResponse *response = nil;
    [self.client getPath:@"/basic-auth/username/password" parameters:nil success:nil failure:^(AFHPHTTPRequestOperation *operation, NSError *error) {
        response = operation.response;
    }];

    expect(response.statusCode).will.equal(401);
}

- (void)testAuthorizationHeaderWithValidUsernamePassword {
    [Expecta setAsynchronousTestTimeout:5.0];

    __block NSHTTPURLResponse *response = nil;
    [self.client setAuthorizationHeaderWithUsername:@"username" password:@"password"];
    [self.client getPath:@"/basic-auth/username/password" parameters:nil success:^(AFHPHTTPRequestOperation *operation, id responseObject) {
        response = operation.response;
    } failure:nil];

    expect(response.statusCode).will.equal(200);
}

- (void)testThatClientClearsAuthorizationHeader {
    [self.client setAuthorizationHeaderWithUsername:@"username" password:@"password"];
    [self.client clearAuthorizationHeader];

    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    expect([request valueForHTTPHeaderField:@"Authorization"]).to.beNil();
}

- (void)testThatClientUsesDefaultCredential {
    NSURLCredential *credential = [NSURLCredential credentialWithUser:@"username" password:@"password" persistence:NSURLCredentialPersistenceNone];
    [self.client setDefaultCredential:credential];

    NSURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/basic-auth/username/password" parameters:nil];
    AFHPHTTPRequestOperation *operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    expect(operation.credential).will.equal(credential);
}

- (void)testAFQueryStringFromParametersWithEncodingWithPlainDictionary {
    NSString *query = AFHPQueryStringFromParametersWithEncoding(@{ @"key": @"value" }, NSUTF8StringEncoding);
    expect(query).to.equal(@"key=value");
}

- (void)testAFQueryStringFromParametersWithEncodingWithComplexNestedParameters {
    NSString *query = AFHPQueryStringFromParametersWithEncoding(@{ @"key1": @"value1", @"key2": @{ @"key": @[ @1, @"value" ] } }, NSUTF8StringEncoding);
    expect(query).to.equal(@"key1=value1&key2[key][]=1&key2[key][]=value");
}

- (void)testThatAFQueryStringFromParametersWithEncodingAppliesPercentEscapes {
    NSString *query = AFHPQueryStringFromParametersWithEncoding(@{ @"key1": @"ä" }, NSUTF8StringEncoding);
    expect(query).to.equal([@"key1=ä" stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]);
}

- (void)testThatCancelAllHTTPOperationsWithMethodPathCancelsOnlyMatchingOperations {
    [self.client registerHTTPOperationClass:[AFHPJSONRequestOperation class]];
    [self.client registerHTTPOperationClass:[AFHPImageRequestOperation class]];

    NSMutableURLRequest *firstRequest = [self.client requestWithMethod:@"GET" path:@"/ip" parameters:nil];
    NSMutableURLRequest *secondRequest = [self.client requestWithMethod:@"GET" path:@"/path" parameters:nil];
    NSMutableURLRequest *thirdRequest = [self.client requestWithMethod:@"POST" path:@"/path" parameters:nil];

    [self.client enqueueBatchOfHTTPRequestOperationsWithRequests:@[ firstRequest, secondRequest, thirdRequest ] progressBlock:nil completionBlock:nil];
    [self.client.operationQueue setSuspended:YES];

    [self.client cancelAllHTTPOperationsWithMethod:@"GET" path:@"/path"];

    NSUInteger numberOfCancelledOperations = [[self.client.operationQueue.operations indexesOfObjectsPassingTest:^BOOL(NSOperation *operation, NSUInteger idx, BOOL *stop) {
        return [operation isCancelled];
    }] count];
    expect(numberOfCancelledOperations).to.equal(1);
}

- (void)testThatTheDefaultStringEncodingIsUTF8 {
    expect(self.client.stringEncoding).to.equal(NSUTF8StringEncoding);
}

- (void)testConstructingPOSTRequestWithParametersInFormURLParameterEncoding {
    self.client.parameterEncoding = AFHPFormURLParameterEncoding;

    NSMutableURLRequest *request = [self.client requestWithMethod:@"POST" path:@"/post" parameters:@{ @"key": @"value" }];
    NSString *requestBody = [[NSString alloc] initWithData:[request HTTPBody] encoding:NSUTF8StringEncoding];
    expect(requestBody).to.equal(@"key=value");
}

- (void)testConstructingPOSTRequestWithParametersInJSONParameterEncoding {
    self.client.parameterEncoding = AFHPJSONParameterEncoding;

    NSMutableURLRequest *request = [self.client requestWithMethod:@"POST" path:@"/post" parameters:@{ @"key": @"value" }];
    NSString *requestBody = [[NSString alloc] initWithData:[request HTTPBody] encoding:NSUTF8StringEncoding];
    expect(requestBody).to.equal(@"{\"key\":\"value\"}");
}

- (void)testConstructingPOSTRequestWithParametersInPropertyListParameterEncoding {
    self.client.parameterEncoding = AFHPPropertyListParameterEncoding;

    NSMutableURLRequest *request = [self.client requestWithMethod:@"POST" path:@"/post" parameters:@{ @"key": @"value" }];
    NSString *requestBody = [[NSString alloc] initWithData:[request HTTPBody] encoding:NSUTF8StringEncoding];
    expect(requestBody).to.equal(@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n	<key>key</key>\n	<string>value</string>\n</dict>\n</plist>\n");
}

- (void)testPostWithParameters {
    __block id blockResponseObject = nil;
    [self.client postPath:@"/post" parameters:@{ @"key": @"value" } success:^(AFHPHTTPRequestOperation *operation, id responseObject) {
        blockResponseObject = responseObject;
    } failure:nil];

    expect([self.client.operationQueue operationCount]).will.equal(0);
    expect(blockResponseObject).notTo.beNil();
    expect(blockResponseObject).to.beKindOf([NSData class]);

    NSError *error = nil;
    NSDictionary *responseDictionary = [NSJSONSerialization JSONObjectWithData:blockResponseObject options:0 error:&error];
    expect([responseDictionary valueForKey:@"form"]).to.equal(@{ @"key": @"value" });
}

- (void)testThatEnqueueBatchOfHTTPRequestOperationsConstructsOperationsWithAppropriateRegisteredHTTPRequestOperationClasses {
    [self.client registerHTTPOperationClass:[AFHPJSONRequestOperation class]];
    [self.client registerHTTPOperationClass:[AFHPImageRequestOperation class]];

    NSMutableURLRequest *firstRequest = [self.client requestWithMethod:@"GET" path:@"/" parameters:nil];
    [firstRequest setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    NSMutableURLRequest *secondRequest = [self.client requestWithMethod:@"GET" path:@"/" parameters:nil];
    [secondRequest setValue:@"image/png" forHTTPHeaderField:@"Accept"];

    __block NSArray *operations = nil;
    id mockClient = [OCMockObject partialMockForObject:self.client];
    void (^block)(NSInvocation *) = ^(NSInvocation *invocation) {
        __unsafe_unretained id argument = nil;
        [invocation getArgument:&argument atIndex:2];

        operations = argument;
    };
    [[[mockClient stub] andDo:block] enqueueBatchOfHTTPRequestOperations:[OCMArg any] progressBlock:nil completionBlock:nil];
    [mockClient enqueueBatchOfHTTPRequestOperationsWithRequests:@[ firstRequest, secondRequest ] progressBlock:nil completionBlock:nil];

    expect(operations).notTo.beNil();
    expect(operations).to.haveCountOf(2);

    expect([[operations objectAtIndex:0] class]).to.equal([AFHPJSONRequestOperation class]);
    expect([[operations objectAtIndex:1] class]).to.equal([AFHPImageRequestOperation class]);
}

- (void)testThatEnqueueBatchOfHTTPRequestOperationsEnqueuesOperationsInTheCorrectOrder {
    NSMutableURLRequest *request = [self.client requestWithMethod:@"GET" path:@"/" parameters:nil];
    AFHPHTTPRequestOperation *firstOperation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];
    AFHPHTTPRequestOperation *secondOperation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];

    id mockClient = [OCMockObject partialMockForObject:self.client];
    id mockOperationQueue = [OCMockObject mockForClass:[NSOperationQueue class]];
    [[[mockClient stub] andReturn:mockOperationQueue] operationQueue];

    __block NSArray *operations = nil;
    [[[mockOperationQueue stub] andDo:^(NSInvocation *invocation) {
        __unsafe_unretained id argument = nil;
        [invocation getArgument:&argument atIndex:2];

        operations = argument;
    }] addOperations:OCMOCK_ANY waitUntilFinished:NO];

    __block NSBlockOperation *batchedOperation = nil;
    [[[mockOperationQueue stub] andDo:^(NSInvocation *invocation) {
        __unsafe_unretained id argument = nil;
        [invocation getArgument:&argument atIndex:2];

        batchedOperation = argument;
    }] addOperation:OCMOCK_ANY];
    [mockClient enqueueBatchOfHTTPRequestOperations:@[ firstOperation, secondOperation ] progressBlock:nil completionBlock:nil];

    expect(operations).to.haveCountOf(2);

    expect([operations objectAtIndex:0]).to.equal(firstOperation);
    expect([operations objectAtIndex:1]).to.equal(secondOperation);

    expect(batchedOperation).notTo.beNil();
    expect(batchedOperation).to.beKindOf([NSBlockOperation class]);
}

- (void)testMultipartUploadDoesNotFailDueToStreamSentAnEventBeforeBeingOpenedError {
    NSString *pathToImage = [[NSBundle bundleForClass:[AFHPHTTPSessionManager class]] pathForResource:@"Icon" ofType:@"png"];
    NSData *imageData = [NSData dataWithContentsOfFile:pathToImage];
    NSMutableURLRequest *request = [self.client multipartFormRequestWithMethod:@"POST" path:@"/post" parameters:@{ @"foo": @"bar" } constructingBodyWithBlock:^(id<AFHPMultipartFormData> formData) {
        [formData appendPartWithFileData:imageData name:@"icon[image]" fileName:@"icon.png" mimeType:@"image/png"];
    }];
    AFHPHTTPRequestOperation *operation = [self.client HTTPRequestOperationWithRequest:request success:nil failure:nil];

    [self.client enqueueHTTPRequestOperation:operation];
    expect(operation.isFinished).will.beTruthy();
    expect(operation.error).notTo.equal(NSURLErrorTimedOut);
}

@end
