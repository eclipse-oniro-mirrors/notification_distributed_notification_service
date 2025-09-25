/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <thread>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "advanced_datashare_helper.h"
#include "notification_check_request.h"
#include "notification_constant.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {

class AdvancedNotificationExtensionSubscriptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationExtensionSubscriptionTest::advancedNotificationService_ =
    nullptr;

void AdvancedNotificationExtensionSubscriptionTest::SetUpTestCase() {}

void AdvancedNotificationExtensionSubscriptionTest::TearDownTestCase() {}

void AdvancedNotificationExtensionSubscriptionTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();

    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationExtensionSubscriptionTest::TearDown()
{
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: NotificationExtensionSubscribe_0100
 * @tc.desc: Test NotificationExtensionSubscribe without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0100,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0200
 * @tc.desc: Test NotificationExtensionSubscribe with empty infos.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0200,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0300
 * @tc.desc: Test NotificationExtensionSubscribe with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0300,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0400
 * @tc.desc: Test NotificationExtensionSubscribe without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0400,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0500
 * @tc.desc: Test NotificationExtensionSubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0500,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0600
 * @tc.desc: Test NotificationExtensionSubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0600,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0100
 * @tc.desc: Test NotificationExtensionUnsubscribe without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0100,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0200
 * @tc.desc: Test NotificationExtensionUnsubscribe with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0200,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0300
 * @tc.desc: Test NotificationExtensionUnsubscribe without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0300,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: NotificationExtensionUnsubscribe_0400
 * @tc.desc: Test NotificationExtensionUnsubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionUnsubscribe_0400,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetSubscribeInfo_0100
 * @tc.desc: Test GetSubscribeInfo without permission.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetSubscribeInfo_0200
 * @tc.desc: Test GetSubscribeInfo with no bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
    MockIsNonBundleName(false);
}

/**
 * @tc.name: GetSubscribeInfo_0300
 * @tc.desc: Test GetSubscribeInfo without queue.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetSubscribeInfo_0400
 * @tc.desc: Test GetSubscribeInfo.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetSubscribeInfo_0400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    ASSERT_EQ(ret, (int)ERR_OK);
}

}
}