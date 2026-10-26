/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"
#define private public
#include "advanced_notification_service.h"
#include "ans_service_errors.h"
#include "mock_accesstoken_kit.h"
#include "mock_ipc_skeleton.h"
#include "notification_bundle_option.h"
#include "notification_request.h"
#include "notification_record.h"
#include "notification_parameters.h"
#include "string_wrapper.h"

using namespace testing::ext;
extern void MockGetOsAccountLocalIdFromUid(bool mockRet, uint8_t mockCase = 0);

extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

namespace OHOS {
namespace Notification {
extern void MockIsNonBundleName(bool isNonBundleName);

class AdvancedNotificationQueryTest : public testing::Test {
public:
    void SetUp() override
    {
        MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
        MockIsSystemApp(true);
        MockIsVerfyPermisson(true);
    }
    void TearDown() override {}
};

static sptr<AdvancedNotificationService> GetService()
{
    return new AdvancedNotificationService();
}

static std::shared_ptr<NotificationRecord> CreateActiveNotificationRecord(
    const sptr<AdvancedNotificationService> &service, const std::string &bundleName,
    int32_t uid, const std::string &instanceKey, bool withRequest)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    if (request == nullptr) {
        return nullptr;
    }
    request->SetNotificationId(1);
    request->SetOwnerBundleName(bundleName);
    request->SetOwnerUid(uid);
    request->SetAppInstanceKey(instanceKey);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    additionalData->SetParam("appKey", AAFwk::String::Box("appValue"));
    request->SetAdditionalData(additionalData);
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    want->SetUri("test://uri");
    request->SetWantAgent(std::make_shared<AbilityRuntime::WantAgent::WantAgent>(
        std::make_shared<AbilityRuntime::WantAgent::LocalPendingWant>(bundleName, want, 0)));

    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    auto record = service->MakeNotificationRecord(request, bundle);
    if (record == nullptr) {
        return nullptr;
    }
    if (!withRequest) {
        record->request = nullptr;
    }
    return record;
}


/**
 * @tc.name: GetAllActiveNotifications_PermissionDenied_00001
 * @tc.desc: Test GetAllActiveNotifications with permission denied
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetAllActiveNotifications_PermissionDenied_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    auto service = GetService();
    std::vector<sptr<Notification>> notifications;

    auto result = service->GetAllActiveNotifications(notifications);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: ExtractWantAgentInfo_NullWantAgent_00001
 * @tc.desc: Test ExtractWantAgentInfo with nullptr wantAgent
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, ExtractWantAgentInfo_NullWantAgent_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->request = new NotificationRequest();
    sptr<NotificationParameters> parameters = new NotificationParameters();

    service->ExtractWantAgentInfo(record, parameters);
    EXPECT_NE(parameters, nullptr);
}

/**
 * @tc.name: GetAllNotificationsBySlotType_CheckPermissionFailed_00001
 * @tc.desc: Test GetAllNotificationsBySlotType with permission check failed
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest,
    GetAllNotificationsBySlotType_CheckPermissionFailed_00001, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    MockIsSystemApp(false);
    auto service = GetService();
    std::vector<sptr<Notification>> notifications;
    int32_t userId = 100;

    auto result = service->GetAllNotificationsBySlotType(notifications,
        static_cast<int32_t>(NotificationConstant::SlotType::SERVICE_REMINDER), userId);
    EXPECT_EQ(result, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.name: QueryNotificationParameters_NullRecord_00001
 * @tc.desc: Test QueryNotificationParameters with null record
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_NullRecord_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_NE(result, ERR_OK);
}

/**
 * @tc.name: QueryNotificationParameters_GetOsAccountFailed_00001
 * @tc.desc: Test QueryNotificationParameters when GetOsAccountLocalIdFromUid fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_GetOsAccountFailed_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(false, 0);
    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: QueryNotificationParameters_InvalidUserId_00001
 * @tc.desc: Test QueryNotificationParameters when userId is invalid (<= 0)
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, QueryNotificationParameters_InvalidUserId_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationParameters> parameters = new NotificationParameters();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("testBundle", 100);

    MockGetOsAccountLocalIdFromUid(true, 1); // mock invalid userId (-2)
    auto result = service->QueryNotificationParameters(1, "testLabel", bundle, parameters);
    EXPECT_EQ(result, ERR_ANS_INNER_GET_ACTIVE_USER_FAILED);
    MockGetOsAccountLocalIdFromUid(true, 0); // reset to default for subsequent tests
}

/**
 * @tc.name: GetActiveNotificationByFilter_NullBundleOption_00001
 * @tc.desc: Test GetActiveNotificationByFilter with nullptr bundleOption
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_NullBundleOption_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(nullptr, 1, "label", 0, extraInfoKeys, request);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);
}

/**
 * @tc.name: GetActiveNotificationByFilter_InvalidBundleWithUserIdInit_00001
 * @tc.desc: Test GetActiveNotificationByFilter with invalid bundleOption and userId -1
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_InvalidBundleWithUserIdInit_00001,
    Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    auto service = GetService();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundleName", 0);
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(bundleOption, 1, "label", -1, extraInfoKeys, request);
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);
    MockQueryForgroundOsAccountId(true, 0);
}

/**
 * @tc.name: GetActiveNotificationByFilter_FallbackBundleCreated_00001
 * @tc.desc: Test GetActiveNotificationByFilter creates fallback bundle when bundleOption is valid
 *           but GenerateValidBundleOption fails
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotificationByFilter_FallbackBundleCreated_00001,
    Function | SmallTest | Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    auto service = GetService();
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("testBundleName", 0);
    sptr<NotificationRequest> request;
    std::vector<std::string> extraInfoKeys;

    auto result = service->GetActiveNotificationByFilter(bundleOption, 1, "label", 0, extraInfoKeys, request);
    EXPECT_NE(result, ERR_ANS_INNER_INVALID_BUNDLE);
    MockQueryForgroundOsAccountId(true, 0);
}


constexpr const char *WANT_URI_PARAM = "ohos.notificationManager.wantUri";

/**
 * @tc.name: BuildRequestWithUriTest_0100
 * @tc.desc: Test BuildRequestWithUri function with nullptr additionalData.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0100, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.GetRefPtr(), request.GetRefPtr());
    EXPECT_EQ(result->GetAdditionalData(), nullptr);
}

/**
 * @tc.name: BuildRequestWithUriTest_0200
 * @tc.desc: Test BuildRequestWithUri function with nullptr wantAgent.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0200, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    ASSERT_NE(additionalData, nullptr);
    request->SetAdditionalData(additionalData);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.GetRefPtr(), request.GetRefPtr());
    // The source request must not be modified.
    EXPECT_FALSE(additionalData->HasParam(WANT_URI_PARAM));
    auto resultData = result->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    EXPECT_NE(resultData, additionalData);
    auto value = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(value, nullptr);
    auto strValue = AAFwk::IString::Query(value);
    ASSERT_NE(strValue, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(strValue), "");
}

/**
 * @tc.name: BuildRequestWithUriTest_0300
 * @tc.desc: Test BuildRequestWithUri function with empty wantAgent.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0300, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    ASSERT_NE(additionalData, nullptr);
    request->SetAdditionalData(additionalData);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>();
    ASSERT_NE(wantAgent, nullptr);
    request->SetWantAgent(wantAgent);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.GetRefPtr(), request.GetRefPtr());
    EXPECT_FALSE(additionalData->HasParam(WANT_URI_PARAM));
    auto resultData = result->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    auto value = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(value, nullptr);
    auto strValue = AAFwk::IString::Query(value);
    ASSERT_NE(strValue, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(strValue), "");
}

/**
 * @tc.name: BuildRequestWithUriTest_0400
 * @tc.desc: Test BuildRequestWithUri function with empty uri in want.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0400, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    ASSERT_NE(additionalData, nullptr);
    request->SetAdditionalData(additionalData);

    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    std::shared_ptr<AbilityRuntime::WantAgent::LocalPendingWant> localPendingWant =
        std::make_shared<AbilityRuntime::WantAgent::LocalPendingWant>("TestBundleName", want, 0);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    ASSERT_NE(wantAgent, nullptr);
    request->SetWantAgent(wantAgent);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.GetRefPtr(), request.GetRefPtr());
    EXPECT_FALSE(additionalData->HasParam(WANT_URI_PARAM));
    auto resultData = result->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    auto value = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(value, nullptr);
    auto strValue = AAFwk::IString::Query(value);
    ASSERT_NE(strValue, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(strValue), "");
}

/**
 * @tc.name: BuildRequestWithUriTest_0500
 * @tc.desc: Test BuildRequestWithUri function with uri in want.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0500, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    ASSERT_NE(additionalData, nullptr);
    request->SetAdditionalData(additionalData);

    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    want->SetUri("test");
    std::shared_ptr<AbilityRuntime::WantAgent::LocalPendingWant> localPendingWant =
        std::make_shared<AbilityRuntime::WantAgent::LocalPendingWant>("TestBundleName", want, 0);
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>(localPendingWant);
    ASSERT_NE(wantAgent, nullptr);
    request->SetWantAgent(wantAgent);

    auto result = service->BuildRequestWithUri(request);
    ASSERT_NE(result, nullptr);
    EXPECT_NE(result.GetRefPtr(), request.GetRefPtr());
    EXPECT_FALSE(additionalData->HasParam(WANT_URI_PARAM));
    auto resultData = result->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    auto value = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(value, nullptr);
    auto strValue = AAFwk::IString::Query(value);
    ASSERT_NE(strValue, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(strValue), "test");
}

/**
 * @tc.name: BuildRequestWithUriTest_0600
 * @tc.desc: Test BuildRequestWithUri function with nullptr request.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, BuildRequestWithUriTest_0600, Function | SmallTest | Level1)
{
    auto service = GetService();
    sptr<NotificationRequest> request = nullptr;

    auto result = service->BuildRequestWithUri(request);
    EXPECT_EQ(result.GetRefPtr(), nullptr);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_500
 * @tc.desc: Test GetNotificationRequestByHashCode returns a private copy and does not
 *           modify the request stored in notificationList_.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetNotificationRequestByHashCode_500, Function | SmallTest | Level1)
{
    auto service = GetService();
    const std::string bundleName = "com.test.bundle";
    const int32_t uid = 100;

    sptr<NotificationRequest> storedRequest = new (std::nothrow) NotificationRequest();
    ASSERT_NE(storedRequest, nullptr);
    storedRequest->SetNotificationId(1);
    storedRequest->SetOwnerBundleName(bundleName);
    storedRequest->SetOwnerUid(uid);
    auto additionalData = std::make_shared<AAFwk::WantParams>();
    ASSERT_NE(additionalData, nullptr);
    additionalData->SetParam("appKey", AAFwk::String::Box("appValue"));
    storedRequest->SetAdditionalData(additionalData);

    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    want->SetUri("test://uri");
    std::shared_ptr<AbilityRuntime::WantAgent::LocalPendingWant> localPendingWant =
        std::make_shared<AbilityRuntime::WantAgent::LocalPendingWant>(bundleName, want, 0);
    storedRequest->SetWantAgent(
        std::make_shared<AbilityRuntime::WantAgent::WantAgent>(localPendingWant));

    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(bundleName, uid);
    auto record = service->MakeNotificationRecord(storedRequest, bundle);
    ASSERT_NE(record, nullptr);
    ASSERT_NE(record->notification, nullptr);
    service->notificationList_.push_back(record);

    sptr<NotificationRequest> request = nullptr;
    auto ret = service->GetNotificationRequestByHashCode(record->notification->GetKey(), request);

    ASSERT_EQ(ret, ERR_OK);
    ASSERT_NE(request, nullptr);
    EXPECT_NE(request.GetRefPtr(), storedRequest.GetRefPtr());
    // The stored request must not be polluted by the query only field.
    EXPECT_FALSE(additionalData->HasParam(WANT_URI_PARAM));
    // The returned copy keeps the original extra data and carries the want uri.
    auto resultData = request->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    EXPECT_TRUE(resultData->HasParam("appKey"));
    auto uriValue = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(uriValue, nullptr);
    auto uriStr = AAFwk::IString::Query(uriValue);
    ASSERT_NE(uriStr, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(uriStr), "test://uri");
}


/**
 * @tc.name: GetActiveNotifications_InvalidBundle_00001
 * @tc.desc: Test GetActiveNotifications when the caller bundle can not be resolved.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotifications_InvalidBundle_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsNonBundleName(true);
    std::vector<sptr<NotificationRequest>> notifications;

    auto result = service->GetActiveNotifications(notifications, "");
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_BUNDLE);

    MockIsNonBundleName(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.name: GetActiveNotifications_QueueInvalid_00001
 * @tc.desc: Test GetActiveNotifications when the ffrt queue is invalid.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotifications_QueueInvalid_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    service->notificationSvrQueue_.Reset();
    std::vector<sptr<NotificationRequest>> notifications;

    auto result = service->GetActiveNotifications(notifications, "");
    EXPECT_EQ(result, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.name: GetActiveNotifications_FilterAndCopy_00001
 * @tc.desc: Test GetActiveNotifications only returns a private copy for the matched records.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetActiveNotifications_FilterAndCopy_00001, Function | SmallTest | Level1)
{
    auto service = GetService();
    const int32_t callingUid = 100;
    IPCSkeleton::SetCallingUid(callingUid);

    auto otherBundle = CreateActiveNotificationRecord(service, "otherBundle", callingUid, "", true);
    auto otherUid = CreateActiveNotificationRecord(service, "", callingUid + 1, "", true);
    auto otherInstance = CreateActiveNotificationRecord(service, "", callingUid, "instance", true);
    auto nullRequest = CreateActiveNotificationRecord(service, "", callingUid, "", false);
    auto matched = CreateActiveNotificationRecord(service, "", callingUid, "", true);
    ASSERT_NE(matched, nullptr);
    service->notificationList_.push_back(otherBundle);
    service->notificationList_.push_back(otherUid);
    service->notificationList_.push_back(otherInstance);
    service->notificationList_.push_back(nullRequest);
    service->notificationList_.push_back(matched);

    std::vector<sptr<NotificationRequest>> notifications;
    auto result = service->GetActiveNotifications(notifications, "");
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(notifications.size(), 1);
    EXPECT_NE(notifications[0].GetRefPtr(), matched->request.GetRefPtr());
    auto storedData = matched->request->GetAdditionalData();
    ASSERT_NE(storedData, nullptr);
    EXPECT_FALSE(storedData->HasParam(WANT_URI_PARAM));
    auto resultData = notifications[0]->GetAdditionalData();
    ASSERT_NE(resultData, nullptr);
    auto value = resultData->GetParam(WANT_URI_PARAM);
    ASSERT_NE(value, nullptr);
    auto strValue = AAFwk::IString::Query(value);
    ASSERT_NE(strValue, nullptr);
    EXPECT_EQ(AAFwk::String::Unbox(strValue), "test://uri");

    IPCSkeleton::SetCallingUid(1);
}

/**
 * @tc.name: GetNotificationRequestByHashCode_NullRequest_00001
 * @tc.desc: Test GetNotificationRequestByHashCode when the matched record has no request.
 * @tc.type: FUNC
 * @tc.require: I00001
 */
HWTEST_F(AdvancedNotificationQueryTest, GetNotificationRequestByHashCode_NullRequest_00001,
    Function | SmallTest | Level1)
{
    auto service = GetService();
    const std::string bundleName = "com.test.bundle";
    sptr<NotificationRequest> storedRequest = new (std::nothrow) NotificationRequest();
    ASSERT_NE(storedRequest, nullptr);
    storedRequest->SetNotificationId(1);
    storedRequest->SetOwnerBundleName(bundleName);
    storedRequest->SetOwnerUid(100);

    sptr<NotificationBundleOption> bundle = new (std::nothrow) NotificationBundleOption(bundleName, 100);
    auto record = service->MakeNotificationRecord(storedRequest, bundle);
    ASSERT_NE(record, nullptr);
    ASSERT_NE(record->notification, nullptr);
    service->notificationList_.push_back(record);
    record->request = nullptr;

    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    ASSERT_NE(request, nullptr);
    auto ret = service->GetNotificationRequestByHashCode(record->notification->GetKey(), request);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(request.GetRefPtr(), nullptr);
}

}  // namespace Notification
}  // namespace OHOS
