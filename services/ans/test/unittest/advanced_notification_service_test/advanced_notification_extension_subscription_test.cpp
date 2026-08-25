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

#include <chrono>
#include <thread>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "ans_service_errors.h"
#include "advanced_datashare_helper.h"
#include "notification_bluetooth_helper.h"
#include "notification_check_request.h"
#include "notification_constant.h"
#include "notification_load_utils.h"
#include "notification_preferences.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"
#include "mock_bluetooth.h"
#include "mock_os_account_manager.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
NotificationLoadUtils::~NotificationLoadUtils()
{
    proxyHandle_ = nullptr;
}

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
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
}

void AdvancedNotificationExtensionSubscriptionTest::TearDown()
{
    if (advancedNotificationService_ != nullptr) {
        advancedNotificationService_->SelfClean(false);
    }
    auto pref = NotificationPreferences::GetInstance();
    if (pref != nullptr) {
        pref->StopCacheCleanupTimer();
    }
    advancedNotificationService_ = nullptr;
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY);
}

/**
 * @tc.name: NotificationExtensionSubscribe_0600
 * @tc.desc: Test NotificationExtensionSubscribe.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribe_0600,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.emplace_back(new (std::nothrow) NotificationExtensionSubscriptionInfo());
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    auto ret = advancedNotificationService_->NotificationExtensionSubscribe(infos);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.name: ProcessExtensionSubscriptionInfos_0100
 * @tc.desc: Test ProcessExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessExtensionSubscriptionInfos_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    info->SetHfp(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    advancedNotificationService_->supportHfp_ = true;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    ErrCode ret = ERR_OK;
    advancedNotificationService_->ProcessExtensionSubscriptionInfos(nullptr, infos, ret);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    EXPECT_TRUE(info->IsHfp());
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
}

/**
 * @tc.name: ProcessExtensionSubscriptionInfos_0200
 * @tc.desc: Test ProcessExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessExtensionSubscriptionInfos_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    info->SetHfp(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    advancedNotificationService_->supportHfp_ = false;
    ErrCode ret = ERR_OK;
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption("bundleName.ProcessExtensionSubscriptionInfos.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->ProcessExtensionSubscriptionInfos(bundleOption, infos, ret);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(info->IsHfp());
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.name: ProcessExtensionSubscriptionInfos_0300
 * @tc.desc: Test ProcessExtensionSubscriptionInfos.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessExtensionSubscriptionInfos_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption("bundleName.ProcessExtensionSubscriptionInfos.0300", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundleOption);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->ProcessExtensionSubscriptionInfos(bundleOption, infos, ret);
    EXPECT_EQ(ret, ERR_OK);
#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
    EXPECT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
#else
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
#endif
    MockIsVerfyPermisson(false);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->NotificationExtensionUnsubscribe();
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    EXPECT_EQ(ret, (int)ERR_OK);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->GetSubscribeInfo(infos);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
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
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest_00001
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00100, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : IsUserGranted_00200
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00200, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.number    : IsUserGranted_00300
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00300, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : IsUserGranted_00400
 * @tc.name      : IsUserGranted
 * @tc.desc      : Test IsUserGranted
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsUserGranted_00400, Function | SmallTest | Level1)
{
    bool isEnabled = false;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    auto bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, SYSTEM_APP_UID);
    auto record = advancedNotificationService_->MakeNotificationRecord(new (std::nothrow) NotificationRequest(),
        bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    auto ret = advancedNotificationService_->IsUserGranted(isEnabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.number    : GetUserGrantedState_0100
 * @tc.name      : GetUserGrantedState
 * @tc.desc      : Test GetUserGrantedState
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0100, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : GetUserGrantedState_0200
 * @tc.name      : GetUserGrantedState_NoPermission
 * @tc.desc      : Test GetUserGrantedState without permission
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0200, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetUserGrantedState_0300
 * @tc.name      : GetUserGrantedState_InvalidBundle
 * @tc.desc      : Test GetUserGrantedState with invalid bundle
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0300, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedState_0400
 * @tc.name      : GetUserGrantedState_NullQueue
 * @tc.desc      : Test GetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedState_0500
 * @tc.name      : GetUserGrantedState ERR_ANS_INNER_INVALID_BUNDLE_OPTION
 * @tc.desc      : Test GetUserGrantedState ERR_ANS_INNER_INVALID_BUNDLE_OPTION case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(invalidBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedState_0600
 * @tc.name      : GetUserGrantedState_Success
 * @tc.desc      : Test GetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedState_0600, Function | SmallTest | Level1)
{
    bool enabled = false;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedState_0100
 * @tc.name      : SetUserGrantedState_NonSystemApp
 * @tc.desc      : Test SetUserGrantedState for non-system app
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0100, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SetUserGrantedState_0200
 * @tc.name      : SetUserGrantedState_NoPermission
 * @tc.desc      : Test SetUserGrantedState without permission
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0200, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", 1001);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetUserGrantedState_0300
 * @tc.name      : SetUserGrantedState_InvalidBundle
 * @tc.desc      : Test SetUserGrantedState with invalid bundle
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0300, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = nullptr;

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedState_0400
 * @tc.name      : SetUserGrantedState_NullQueue
 * @tc.desc      : Test SetUserGrantedState with null queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0400, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedState_0500
 * @tc.name      : SetUserGrantedState ERR_ANS_INNER_INVALID_BUNDLE_OPTION
 * @tc.desc      : Test SetUserGrantedState ERR_ANS_INNER_INVALID_BUNDLE_OPTION case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0500, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(invalidBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedState_0600
 * @tc.name      : SetUserGrantedState_Success
 * @tc.desc      : Test SetUserGrantedState success case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedState_0600, Function | SmallTest | Level1)
{
    bool enabled = true;
    sptr<NotificationBundleOption> targetBundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->SetUserGrantedState(targetBundle, enabled);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0100
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0100, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, extensionBundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(nullptr, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->GetUserGrantedEnabledBundles(invalidBundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0200
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0200, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundles_0300
 * @tc.name      : GetUserGrantedEnabledBundles
 * @tc.desc      : Test GetUserGrantedEnabledBundles function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundles_0300, Function | SmallTest |
    Level1)
{
    std::vector<sptr<NotificationBundleOption>> enabledBundles;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);

    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);

    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundles(bundle, enabledBundles);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0100
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0100, Function | SmallTest
    | Level1)
{
    MockIsVerfyPermisson(false);
    std::vector<sptr<NotificationBundleOption>> bundles;
    ErrCode ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0200
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0200, Function | SmallTest
    | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0300
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0300, Function | SmallTest
    | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();

    auto ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : GetUserGrantedEnabledBundlesForSelf_0400
 * @tc.name      : GetUserGrantedEnabledBundlesForSelf
 * @tc.desc      : Test GetUserGrantedEnabledBundlesForSelf function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetUserGrantedEnabledBundlesForSelf_0400, Function | SmallTest
    | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);

    sptr<NotificationBundleOption> bundleOption = advancedNotificationService_->GenerateBundleOption();
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, { bundleOption });
    ret = advancedNotificationService_->GetUserGrantedEnabledBundlesForSelf(bundles);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(bundles.empty());
    MockIsSystemApp(false);
    MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0100
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    auto ret = advancedNotificationService_->SetUserGrantedBundleState(nullptr, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0200
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("extension.bundle1", 1002),
        new NotificationBundleOption("extension.bundle2", 1003)
    };
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", 1001);
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0300
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0400
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> invalidextensionBundles = {
        new NotificationBundleOption("invalidBundle", -1),
    };
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> invalidBundle = new NotificationBundleOption("invalidBundle", -1);

    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(
        invalidBundle, invalidextensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, invalidextensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);

    ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_INVALID_BUNDLE_OPTION);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0500
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : SetUserGrantedBundleState_0600
 * @tc.name      : SetUserGrantedBundleState
 * @tc.desc      : Test SetUserGrantedBundleState function
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SetUserGrantedBundleState_0600, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    std::vector<sptr<NotificationBundleOption>> extensionBundles = {
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID),
    };
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    ErrCode ret = advancedNotificationService_->SetUserGrantedBundleState(bundle, extensionBundles, true);
    EXPECT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0200, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : AdvancedNotificationServiceTest
 * @tc.name      : GetAllSubscriptionBundles
 * @tc.desc      : Test GetAllSubscriptionBundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetAllSubscriptionBundles_0300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->GetAllSubscriptionBundles(bundles);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0100
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0100, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0200
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0200, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY);
}

/**
 * @tc.number    : CanOpenSubscribeSettings_0300
 * @tc.name      : CanOpenSubscribeSettings
 * @tc.desc      : Test CanOpenSubscribeSettings
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CanOpenSubscribeSettings_0300, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    ErrCode ret = advancedNotificationService_->CanOpenSubscribeSettings();
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
}

/**
 * @tc.number    : HasExtensionSubscriptionStateChanged_0100
 * @tc.name      : HasExtensionSubscriptionStateChanged
 * @tc.desc      : Test HasExtensionSubscriptionStateChanged case
 */
 HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HasExtensionSubscriptionStateChanged_0100,
    Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    auto ret = notificationPreferences.SetExtensionSubscriptionEnabled(bundle,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
    EXPECT_EQ(ret, ERR_OK);
    bool ret2 = advancedNotificationService_->HasExtensionSubscriptionStateChanged(bundle, true);
    EXPECT_FALSE(ret2);

    ret2 = advancedNotificationService_->HasExtensionSubscriptionStateChanged(nullptr, true);
    EXPECT_TRUE(ret2);
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0100
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption;
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.push_back(sptr<NotificationExtensionSubscriptionInfo>(
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)));
    bool updateHfp = false;
    ErrCode ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundleOption, infos, updateHfp);

    EXPECT_FALSE(ret);
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0200
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos;
    infos.push_back(sptr<NotificationExtensionSubscriptionInfo>(
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)));
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);

    EXPECT_FALSE(ret);
    advancedNotificationService_->supportHfp_ = false;
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0300
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        nullptr,
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::BLUETOOTH),
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    infos[2]->SetHfp(true);
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);
    EXPECT_FALSE(ret);
    advancedNotificationService_->supportHfp_ = false;
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0400
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);

    EXPECT_TRUE(ret);
    EXPECT_TRUE(updateHfp);
    advancedNotificationService_->supportHfp_ = false;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckBluetoothConnectionInInfos_0500
 * @tc.name      : CheckBluetoothConnectionInInfos
 * @tc.desc      : Test CheckBluetoothConnectionInInfos case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0500, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = {
        new NotificationExtensionSubscriptionInfo("test_addr", NotificationConstant::SubscribeType::BLUETOOTH)
    };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->supportHfp_ = false;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);
    EXPECT_TRUE(ret);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0600, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    auto subscribeInfo = new NotificationExtensionSubscriptionInfo("test_addr",
        NotificationConstant::SubscribeType::BLUETOOTH);
    subscribeInfo->SetHfp(false);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { subscribeInfo };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);

    EXPECT_TRUE(ret);
    EXPECT_TRUE(updateHfp);
    advancedNotificationService_->supportHfp_ = false;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0700, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    auto subscribeInfo = new NotificationExtensionSubscriptionInfo("test_addr",
        NotificationConstant::SubscribeType::BLUETOOTH);
    subscribeInfo->SetHfp(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { subscribeInfo };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(updateHfp);
    advancedNotificationService_->supportHfp_ = false;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConnectionInInfos_0800, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID);
    auto subscribeInfo = new NotificationExtensionSubscriptionInfo("test_addr",
        NotificationConstant::SubscribeType::BLUETOOTH);
    subscribeInfo->SetHfp(true);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { subscribeInfo };
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    advancedNotificationService_->supportHfp_ = true;
    bool updateHfp = false;
    bool ret = advancedNotificationService_->CheckBluetoothConnectionInInfos(bundle, infos, updateHfp);

    EXPECT_FALSE(ret);
    EXPECT_FALSE(updateHfp);
    advancedNotificationService_->supportHfp_ = false;
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}
/**
 * @tc.number    : CheckExtensionServiceCondition_0100
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0100, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles;
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_TRUE(bundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_TRUE(unsubscribedBundles.empty());
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0200
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0200, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles = {
        new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)
    };
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_TRUE(bundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_FALSE(unsubscribedBundles.empty());
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0300
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0300, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    std::vector<sptr<NotificationBundleOption>> bundles = {
        new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)
    };
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    MockIsVerfyPermisson(true);
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_TRUE(bundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_FALSE(unsubscribedBundles.empty());
    MockIsVerfyPermisson(false);
}
/**
 * @tc.number    : CheckExtensionServiceCondition_0400
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0400, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0400", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_TRUE(bundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_FALSE(unsubscribedBundles.empty());
    MockIsVerfyPermisson(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0500
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0500, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0500", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_FALSE(bundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_TRUE(unsubscribedBundles.empty());
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0600
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test CheckExtensionServiceCondition case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0600, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("test.bundle.0600", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_FALSE(bundles.empty());
    EXPECT_FALSE(extensionBundleInfos.empty());
    EXPECT_TRUE(unsubscribedBundles.empty());
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckExtensionServiceCondition_0700
 * @tc.name      : CheckExtensionServiceCondition
 * @tc.desc      : Test priority subscriber bypasses bluetooth filters and is not unsubscribed
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, CheckExtensionServiceCondition_0700, Function | SmallTest | Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption =
        new NotificationBundleOption("test.bundle.0700", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> unsubscribedBundles;
    advancedNotificationService_->CheckExtensionServiceCondition(bundles, extensionBundleInfos, unsubscribedBundles);
    EXPECT_TRUE(unsubscribedBundles.empty());
    EXPECT_TRUE(extensionBundleInfos.empty());
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : SeparatePrioritySubscribers_0100
 * @tc.name      : SeparatePrioritySubscribers
 * @tc.desc      : Test priority subscriber is removed from bundles
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, SeparatePrioritySubscribers_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> priorityBundle =
        new NotificationBundleOption("priority.bundle", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> normalBundle =
        new NotificationBundleOption("normal.bundle", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(priorityBundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> bundles = { priorityBundle, normalBundle };
    advancedNotificationService_->SeparatePrioritySubscribers(bundles);
    EXPECT_EQ(bundles.size(), 1);
    EXPECT_EQ(bundles[0]->GetBundleName(), "normal.bundle");
}

/**
 * @tc.number    : SeparatePrioritySubscribers_0200
 * @tc.name      : SeparatePrioritySubscribers
 * @tc.desc      : Test all bundles are priority subscribers and all removed
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, SeparatePrioritySubscribers_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> priorityBundle =
        new NotificationBundleOption("priority.bundle2", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(priorityBundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> bundles = { priorityBundle };
    advancedNotificationService_->SeparatePrioritySubscribers(bundles);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : IsSystemTypeSubscriber_0100
 * @tc.name      : IsSystemTypeSubscriber
 * @tc.desc      : Test bundle with SYSTEM subscribe type returns true
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, IsSystemTypeSubscriber_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("system.bundle", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(advancedNotificationService_->IsSystemTypeSubscriber(bundle));
}

/**
 * @tc.number    : IsSystemTypeSubscriber_0200
 * @tc.name      : IsSystemTypeSubscriber
 * @tc.desc      : Test bundle without SYSTEM subscribe type returns false
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, IsSystemTypeSubscriber_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("non.system.bundle", NON_SYSTEM_APP_UID);
    EXPECT_FALSE(advancedNotificationService_->IsSystemTypeSubscriber(bundle));
}

/**
 * @tc.number    : FilterPermissionBundles_0100
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    MockIsVerfyPermisson(false);
    advancedNotificationService_->FilterPermissionBundles(bundles, mismatchedBundles);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterPermissionBundles_0200
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0200, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    MockIsVerfyPermisson(true);
    advancedNotificationService_->FilterPermissionBundles(bundles, mismatchedBundles);
    EXPECT_FALSE(bundles.empty());
}

/**
 * @tc.number    : FilterPermissionBundles_0300
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles returns early (bundles unchanged) when resolved
 *                 userId is invalid (< 0)
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0300,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    MockIsVerfyPermisson(true);
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(-1); // invalid userId
    advancedNotificationService_->FilterPermissionBundles(bundles, mismatchedBundles);
    // early return at line 257: the bundle is neither filtered nor moved to mismatchedBundles
    EXPECT_EQ(bundles.size(), 1);
    EXPECT_TRUE(mismatchedBundles.empty());
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(100); // reset to default
}

/**
 * @tc.number    : FilterPermissionBundles_0400
 * @tc.name      : FilterPermissionBundles
 * @tc.desc      : Test FilterPermissionBundles with multiple bundles stops at the first invalid
 *                 userId (remaining bundles are not processed)
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterPermissionBundles_0400,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle.first", NON_SYSTEM_APP_UID)));
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle.second", NON_SYSTEM_APP_UID)));
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    MockIsVerfyPermisson(true);
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(-1); // invalid userId
    advancedNotificationService_->FilterPermissionBundles(bundles, mismatchedBundles);
    // early return: loop aborted at the first bundle, nothing filtered
    EXPECT_EQ(bundles.size(), 2);
    EXPECT_TRUE(mismatchedBundles.empty());
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(100); // reset to default
}

/**
 * @tc.number    : FilterGrantedBundles_0100
 * @tc.name      : FilterGrantedBundles
 * @tc.desc      : Test FilterGrantedBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterGrantedBundles_0100, Function | SmallTest | Level1)
{
    NotificationPreferences notificationPreferences;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);

    auto ret = notificationPreferences.SetExtensionSubscriptionEnabled(bundleOption,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> bundles{ bundleOption };
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    advancedNotificationService_->FilterGrantedBundles(bundles, mismatchedBundles);
    EXPECT_FALSE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0100
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0100,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    bundles.emplace_back(
        sptr<NotificationBundleOption>(new NotificationBundleOption("test.bundle", NON_SYSTEM_APP_UID)));
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles, mismatchedBundles);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0200
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName.0200", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);

    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles, mismatchedBundles);
    EXPECT_TRUE(bundles.empty());
}

/**
 * @tc.number    : FilterBundlesByBluetoothConnection_0300
 * @tc.name      : FilterBundlesByBluetoothConnection
 * @tc.desc      : Test FilterBundlesByBluetoothConnection case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0300,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName.0300", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);

    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles, mismatchedBundles);
    EXPECT_FALSE(bundles.empty());
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, FilterBundlesByBluetoothConnection_0400,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundleName.0300", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);

    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    std::vector<sptr<NotificationBundleOption>> mismatchedBundles;
    advancedNotificationService_->FilterBundlesByBluetoothConnection(bundles, mismatchedBundles);
    EXPECT_FALSE(bundles.empty());
    MockHandsFreeAudioGatewayGetDeviceStateEnabled(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}

/**
 * @tc.number    : CheckBluetoothConditions_0100
 * @tc.name      : CheckBluetoothConditions
 * @tc.desc      : Test CheckBluetoothConditions case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, CheckBluetoothConditions_0100, Function | SmallTest | Level1)
{
    bool ret = NotificationBluetoothHelper::GetInstance().CheckBluetoothConditions("test_addr");
    EXPECT_FALSE(ret);
}

/**
 * @tc.number    : EnsureBundlesCanSubscribeOrUnsubscribe_0100
 * @tc.name      : EnsureBundlesCanSubscribeOrUnsubscribe
 * @tc.desc      : Test EnsureBundlesCanSubscribeOrUnsubscribe case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribeOrUnsubscribe_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    EXPECT_TRUE(advancedNotificationService_->EnsureBundlesCanSubscribeOrUnsubscribe(bundle));
    advancedNotificationService_->UnSubscribeExtensionService(bundle);
}

/**
 * @tc.number    : EnsureBundlesCanSubscribeOrUnsubscribe_0200
 * @tc.name      : EnsureBundlesCanSubscribeOrUnsubscribe
 * @tc.desc      : Test EnsureBundlesCanSubscribeOrUnsubscribe case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribeOrUnsubscribe_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_TRUE(advancedNotificationService_->EnsureBundlesCanSubscribeOrUnsubscribe(bundle));
    advancedNotificationService_->UnSubscribeExtensionService(bundle);
}

/**
 * @tc.number    : EnsureBundlesCanSubscribeOrUnsubscribe_0300
 * @tc.name      : EnsureBundlesCanSubscribeOrUnsubscribe
 * @tc.desc      : Test EnsureBundlesCanSubscribeOrUnsubscribe case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribeOrUnsubscribe_0300,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> subscribeBundles;
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_TRUE(advancedNotificationService_->EnsureBundlesCanSubscribeOrUnsubscribe(bundle));
}

/**
 * @tc.number    : EnsureBundlesCanSubscribeOrUnsubscribe_0400
 * @tc.name      : EnsureBundlesCanSubscribeOrUnsubscribe
 * @tc.desc      : Test EnsureBundlesCanSubscribeOrUnsubscribe case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribeOrUnsubscribe_0400, Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle.Name.0400", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(
        bundleOption, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_TRUE(advancedNotificationService_->EnsureBundlesCanSubscribeOrUnsubscribe(bundleOption));
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
    advancedNotificationService_->UnSubscribeExtensionService(bundleOption);
}

HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribeOrUnsubscribe_0500, Level1)
{
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption("bundle.Name.0400", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundleOption };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundleOption, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundleOption, bundles);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(
        bundleOption, NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_TRUE(advancedNotificationService_->EnsureBundlesCanSubscribeOrUnsubscribe(bundleOption));
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
    advancedNotificationService_->UnSubscribeExtensionService(bundleOption);
}

/**
 * @tc.number    : ShutdownExtensionServiceAndUnSubscribed_0100
 * @tc.name      : ShutdownExtensionServiceAndUnSubscribed
 * @tc.desc      : Test ShutdownExtensionServiceAndUnSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionServiceAndUnSubscribed_0100,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_FALSE(advancedNotificationService_->ShutdownExtensionServiceAndUnSubscribed(bundle));
}

/**
 * @tc.number    : ShutdownExtensionServiceAndUnSubscribed_0200
 * @tc.name      : ShutdownExtensionServiceAndUnSubscribed
 * @tc.desc      : Test ShutdownExtensionServiceAndUnSubscribed case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionServiceAndUnSubscribed_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_TRUE(advancedNotificationService_->ShutdownExtensionServiceAndUnSubscribed(bundle));
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
}

/**
 * @tc.number    : HandleBundleInstall_0100
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->HandleBundleInstall(nullptr);
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleInstall_0200
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->HandleBundleInstall(bundle);
    advancedNotificationService_->SelfClean(false);
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleInstall_0300
 * @tc.name      : HandleBundleInstall
 * @tc.desc      : Test HandleBundleInstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleInstall_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->HandleBundleInstall(bundle);
    advancedNotificationService_->SelfClean(false);
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0100
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID));
    advancedNotificationService_->HandleBundleUpdate(nullptr);
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUpdate_0200
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUpdate_0300
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(0);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    // installedUserId(100) != currentUserId(0): another user's update is skipped, cache stays empty
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100); // reset to default
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0400
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0400,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0500,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    // installedUserId(100) == currentUserId(100): valid update is cached in the extension bundle cache
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0600
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate when GetOsAccountLocalIdFromUid returns invalid userId (< 0)
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0600,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(-1);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    // invalid userId triggers early return at line 503 before caching the bundle
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(100); // reset to default
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUpdate_0700
 * @tc.name      : HandleBundleUpdate
 * @tc.desc      : Test HandleBundleUpdate when installed user differs from current active user
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUpdate_0700,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(101);
    MockOsAccountManager::MockGetForegroundOsAccountLocalId(100);
    advancedNotificationService_->HandleBundleUpdate(bundle);
    advancedNotificationService_->SelfClean(false);
    // another user's package update is skipped at line 508 before caching the bundle
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
    MockOsAccountManager::MockGetOsAccountLocalIdFromUid(100); // reset to default
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : HandleBundleUninstall_0100
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(
        new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID));
    advancedNotificationService_->HandleBundleUninstall(nullptr);
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUninstall_0200
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("bundleName", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->HandleBundleUninstall(bundle);
    advancedNotificationService_->SelfClean(false);
    EXPECT_TRUE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : HandleBundleUninstall_0300
 * @tc.name      : HandleBundleUninstall
 * @tc.desc      : Test HandleBundleUninstall case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, HandleBundleUninstall_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
    sptr<NotificationBundleOption> bundle1 = new NotificationBundleOption("bundleName1", NON_SYSTEM_APP_UID);
    sptr<NotificationBundleOption> bundle2 = new NotificationBundleOption("bundleName2", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle1);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle2);
    advancedNotificationService_->HandleBundleUninstall(bundle1);
    advancedNotificationService_->SelfClean(false);
    EXPECT_FALSE(advancedNotificationService_->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : OnHfpDeviceConnectChanged_0100
 * @tc.name      : OnHfpDeviceConnectChanged
 * @tc.desc      : Test OnHfpDeviceConnectChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnHfpDeviceConnectChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    Bluetooth::BluetoothRemoteDevice device;
    advancedNotificationService_->OnHfpDeviceConnectChanged(
        device, static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : OnBluetoothStateChanged_0100
 * @tc.name      : OnBluetoothStateChanged
 * @tc.desc      : Test OnBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnBluetoothStateChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    advancedNotificationService_->OnBluetoothStateChanged(static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : OnBluetoothPairedStatusChanged_0100
 * @tc.name      : OnBluetoothPairedStatusChanged
 * @tc.desc      : Test OnBluetoothPairedStatusChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnBluetoothPairedStatusChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    Bluetooth::BluetoothRemoteDevice device;
    advancedNotificationService_->OnBluetoothPairedStatusChanged(
        device, static_cast<int32_t>(OHOS::Bluetooth::PAIR_PAIRED));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0100
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0200
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessHfpDeviceStateChange.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessHfpDeviceStateChange_0300
 * @tc.name      : ProcessHfpDeviceStateChange
 * @tc.desc      : Test ProcessHfpDeviceStateChange case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessHfpDeviceStateChange_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessHfpDeviceStateChange.0300", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    advancedNotificationService_->ProcessHfpDeviceStateChange(
        static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0100
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0200
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    EXPECT_FALSE(advancedNotificationService_->notificationExtensionLoaded_.load());
}

/**
 * @tc.number    : ProcessBluetoothStateChanged_0300
 * @tc.name      : ProcessBluetoothStateChanged
 * @tc.desc      : Test ProcessBluetoothStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ProcessBluetoothStateChanged_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    std::vector<std::pair<sptr<NotificationBundleOption>, std::vector<sptr<NotificationBundleOption>>>>
        extensionBundleInfos;
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundleName.ProcessBluetoothStateChanged.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->cacheNotificationExtensionBundles_.emplace_back(bundle);
    std::vector<sptr<NotificationBundleOption>> bundles = { bundle };
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("address", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(bundle, bundles);
    EXPECT_EQ(ret, ERR_OK);
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionEnabled(bundle,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    EXPECT_EQ(ret, ERR_OK);
    MockIsVerfyPermisson(true);
    MockBluetoothRemoteDeviceGetPairStateEnabled(true);
    advancedNotificationService_->ProcessBluetoothStateChanged(
        static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON));
    EXPECT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
    MockIsVerfyPermisson(false);
    MockBluetoothRemoteDeviceGetPairStateEnabled(false);
}
#endif

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0100
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0100,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(false);
    MockIsNeedHapModuleInfos(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    EXPECT_TRUE(bundles.empty());
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0200
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0200,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    for (size_t i = 0; i < bundles.size(); ++i) {
        EXPECT_EQ(bundles[i]->GetBundleName(), "test_bundle");
        EXPECT_EQ(bundles[i]->GetUid(), NON_SYSTEM_APP_UID);
    }
    MockIsNeedHapModuleInfos(false);
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0300
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0300,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    MockGetCloneAppIndexes(true);
    MockGetCloneBundleInfo(true);
    ErrCode ret = advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles);
    for (size_t i = 0; i < bundles.size(); ++i) {
        EXPECT_EQ(bundles[i]->GetBundleName(), "test_bundle");
        EXPECT_EQ(bundles[i]->GetUid(), NON_SYSTEM_APP_UID);
    }
    MockIsNeedHapModuleInfos(false);
    MockGetCloneAppIndexes(false);
    MockGetCloneBundleInfo(false);
    advancedNotificationService_->cacheNotificationExtensionBundles_.clear();
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0400
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0400,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockQueryExtensionAbilityInfos(true, true);
    MockSetBundleInfoFailed(true);
    EXPECT_EQ(advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles), ERR_OK);
    EXPECT_TRUE(bundles.empty());
    MockQueryExtensionAbilityInfos(false, true);
    MockSetBundleInfoFailed(false);
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0500
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0500,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockQueryExtensionAbilityInfos(true, true);
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(false);
    EXPECT_EQ(advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles), ERR_OK);
    EXPECT_TRUE(bundles.empty());
    MockQueryExtensionAbilityInfos(false, true);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : GetNotificationExtensionEnabledBundles_0600
 * @tc.name      : GetNotificationExtensionEnabledBundles
 * @tc.desc      : Test GetNotificationExtensionEnabledBundles case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetNotificationExtensionEnabledBundles_0600,
    Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles;
    MockIsVerfyPermisson(true);
    MockQueryExtensionAbilityInfos(true, true);
    MockSetBundleInfoEnabled(true);
    MockIsNeedHapModuleInfos(true);
    EXPECT_EQ(advancedNotificationService_->GetNotificationExtensionEnabledBundles(bundles), ERR_OK);
    EXPECT_FALSE(bundles.empty());
    MockIsVerfyPermisson(false);
    MockQueryExtensionAbilityInfos(false, true);
    MockSetBundleInfoEnabled(false);
    MockIsNeedHapModuleInfos(false);
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
/**
 * @tc.number    : isExtensionServiceExist_0100
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    EXPECT_FALSE(advancedNotificationService_->isExtensionServiceExist());
}

/**
 * @tc.number    : isExtensionServiceExist_0200
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_FALSE(advancedNotificationService_->isExtensionServiceExist());
}

/**
 * @tc.number    : isExtensionServiceExist_0300
 * @tc.name      : isExtensionServiceExist
 * @tc.desc      : Test isExtensionServiceExist case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, isExtensionServiceExist_0300,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ =
        std::make_shared<NotificationLoadUtils>("does_not_exist.z.so");
    EXPECT_FALSE(advancedNotificationService_->isExtensionServiceExist());
}

/**
 * @tc.number    : LoadExtensionService_0100
 * @tc.name      : LoadExtensionService
 * @tc.desc      : Test LoadExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, LoadExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(true);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
    EXPECT_NE(advancedNotificationService_->notificationExtensionHandler_, nullptr);
}

/**
 * @tc.number    : LoadExtensionService_0200
 * @tc.name      : LoadExtensionService
 * @tc.desc      : Test LoadExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, LoadExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_TRUE(advancedNotificationService_->notificationExtensionLoaded_.load());
    EXPECT_NE(advancedNotificationService_->notificationExtensionHandler_, nullptr);
}

/**
 * @tc.number    : SubscribeExtensionService_0100
 * @tc.name      : SubscribeExtensionService
 * @tc.desc      : Test SubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    EXPECT_EQ(advancedNotificationService_->SubscribeExtensionService(bundle, bundles), -1);
}

/**
 * @tc.number    : SubscribeExtensionService_0200
 * @tc.name      : SubscribeExtensionService
 * @tc.desc      : Test SubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles;
    EXPECT_EQ(advancedNotificationService_->SubscribeExtensionService(bundle, bundles), 0);
}

/**
 * @tc.number    : UnSubscribeExtensionService_0100
 * @tc.name      : UnSubscribeExtensionService
 * @tc.desc      : Test UnSubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, UnSubscribeExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->UnSubscribeExtensionService(bundle), -1);
}

/**
 * @tc.number    : UnSubscribeExtensionService_0200
 * @tc.name      : UnSubscribeExtensionService
 * @tc.desc      : Test UnSubscribeExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, UnSubscribeExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    EXPECT_EQ(advancedNotificationService_->UnSubscribeExtensionService(bundle), 0);
}

/**
 * @tc.number    : ShutdownExtensionService_0100
 * @tc.name      : ShutdownExtensionService
 * @tc.desc      : Test ShutdownExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionService_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->ShutdownExtensionService(), -1);
}

/**
 * @tc.number    : ShutdownExtensionService_0200
 * @tc.name      : ShutdownExtensionService
 * @tc.desc      : Test ShutdownExtensionService case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ShutdownExtensionService_0200,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    EXPECT_EQ(advancedNotificationService_->LoadExtensionService(), 0);
    EXPECT_EQ(advancedNotificationService_->ShutdownExtensionService(), 0);
}

/**
 * @tc.number    : RegisterBluetoothAccessObserver_0100
 * @tc.name      : RegisterBluetoothAccessObserver
 * @tc.desc      : Test RegisterBluetoothAccessObserver case
 */
HWTEST_F(
    AdvancedNotificationExtensionSubscriptionTest, RegisterBluetoothAccessObserver_0100, Function | SmallTest | Level1)
{
    auto &helper = NotificationBluetoothHelper::GetInstance();
    helper.bluetoothAccessObserver_ = nullptr;
    helper.isBluetoothObserverRegistered_.store(false);
    helper.RegisterBluetoothAccessObserver();
    auto firstPtr = helper.bluetoothAccessObserver_;
    EXPECT_NE(firstPtr, nullptr);
    EXPECT_TRUE(helper.isBluetoothObserverRegistered_.load());
    helper.RegisterBluetoothAccessObserver();
    EXPECT_EQ(firstPtr, helper.bluetoothAccessObserver_);
    EXPECT_TRUE(helper.isBluetoothObserverRegistered_.load());
    helper.isBluetoothObserverRegistered_.store(true);
    helper.bluetoothAccessObserver_ = nullptr;
    helper.RegisterBluetoothAccessObserver();
    EXPECT_NE(helper.bluetoothAccessObserver_, nullptr);
}

/**
 * @tc.number    : OnConnectionStateChanged_0100
 * @tc.name      : OnConnectionStateChanged
 * @tc.desc      : Test OnConnectionStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnConnectionStateChanged_0100, Function | SmallTest | Level1)
{
    EXPECT_NE(advancedNotificationService_, nullptr);
    HfpStateObserver observer;
    OHOS::Bluetooth::BluetoothRemoteDevice device("00:11:22:33:44:55", OHOS::Bluetooth::BT_TRANSPORT_NONE);
    observer.OnConnectionStateChanged(device, 1, 0);
    auto singleton = AdvancedNotificationService::GetInstance();
    EXPECT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
    EXPECT_TRUE(singleton->cacheNotificationExtensionBundles_.empty());
}

/**
 * @tc.number    : OnStateChanged_0100
 * @tc.name      : OnStateChanged
 * @tc.desc      : Test OnStateChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnStateChanged_0100, Function | SmallTest | Level1)
{
    EXPECT_NE(advancedNotificationService_, nullptr);
    BluetoothAccessObserver observer;
    observer.OnStateChanged(1, 2);
    auto singleton = AdvancedNotificationService::GetInstance();
    EXPECT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
}

/**
 * @tc.number    : OnPairStatusChanged_0100
 * @tc.name      : OnPairStatusChanged
 * @tc.desc      : Test OnPairStatusChanged case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, OnPairStatusChanged_0100, Function | SmallTest | Level1)
{
    EXPECT_NE(advancedNotificationService_, nullptr);
    BluetoothPairedDeviceObserver observer;
    OHOS::Bluetooth::BluetoothRemoteDevice device("00:11:22:33:44:55", OHOS::Bluetooth::BT_TRANSPORT_NONE);
    observer.OnPairStatusChanged(device, 3, 0);
    auto singleton = AdvancedNotificationService::GetInstance();
    EXPECT_NE(singleton, nullptr);
    EXPECT_FALSE(singleton->notificationExtensionLoaded_);
}

/**
 * @tc.number    : GetCloneBundleList_0100
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, -1);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    EXPECT_FALSE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
}

/**
 * @tc.number    : GetCloneBundleList_0200
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    EXPECT_FALSE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
}

/**
 * @tc.number    : GetCloneBundleList_0300
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    MockGetCloneAppIndexes(true);
    EXPECT_TRUE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_TRUE(cloneBundleList.empty());
    MockGetCloneAppIndexes(false);
}

/**
 * @tc.number    : GetCloneBundleList_0400
 * @tc.name      : GetCloneBundleList
 * @tc.desc      : Test GetCloneBundleList case
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, GetCloneBundleList_0400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundleOption = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> cloneBundleList;
    MockGetCloneAppIndexes(true);
    MockGetCloneBundleInfo(true);
    EXPECT_TRUE(advancedNotificationService_->GetCloneBundleList(bundleOption, cloneBundleList));
    EXPECT_FALSE(cloneBundleList.empty());
    MockGetCloneAppIndexes(false);
    MockGetCloneBundleInfo(false);
}

/**
 * @tc.number    : IsPriorityBundle_0100
 * @tc.name      : IsPriorityBundle
 * @tc.desc      : Test IsPriorityBundle returns false when GetExtensionSubscriptionInfos fails
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsPriorityBundle_0100, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption("test.IsPriorityBundle", NON_SYSTEM_APP_UID);
    bool result = advancedNotificationService_->IsPriorityBundle(bundle);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsPriorityBundle_0200
 * @tc.name      : IsPriorityBundle
 * @tc.desc      : Test IsPriorityBundle returns true when bundle has SYSTEM type subscription info
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsPriorityBundle_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundle.IsPriorityBundle.0200", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    bool result = advancedNotificationService_->IsPriorityBundle(bundle);
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : IsPriorityBundle_0300
 * @tc.name      : IsPriorityBundle
 * @tc.desc      : Test IsPriorityBundle returns false when subscription info has BLUETOOTH type only
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsPriorityBundle_0300, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundle.IsPriorityBundle.0300", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    bool result = advancedNotificationService_->IsPriorityBundle(bundle);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : IsPriorityBundle_0400
 * @tc.name      : IsPriorityBundle
 * @tc.desc      : Test IsPriorityBundle returns false when no SYSTEM type in infos
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, IsPriorityBundle_0400, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundle.IsPriorityBundle.0400", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(bundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    bool result = advancedNotificationService_->IsPriorityBundle(bundle);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : ClassifyExtensionBundles_0100
 * @tc.name      : ClassifyExtensionBundles
 * @tc.desc      : Test ClassifyExtensionBundles with nullptr bundle skipped
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ClassifyExtensionBundles_0100, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationBundleOption>> bundles = { nullptr };
    std::vector<sptr<NotificationBundleOption>> priorityBundles;
    std::vector<sptr<NotificationBundleOption>> normalBundles;
    advancedNotificationService_->ClassifyExtensionBundles(bundles, priorityBundles, normalBundles);
    EXPECT_TRUE(priorityBundles.empty());
    EXPECT_TRUE(normalBundles.empty());
}

/**
 * @tc.number    : ClassifyExtensionBundles_0200
 * @tc.name      : ClassifyExtensionBundles
 * @tc.desc      : Test ClassifyExtensionBundles classifies priority and normal bundles correctly
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ClassifyExtensionBundles_0200, Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> priorityBundle =
        new NotificationBundleOption("bundle.Classify.0200.pri", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::SYSTEM);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(priorityBundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    sptr<NotificationBundleOption> normalBundle =
        new NotificationBundleOption("bundle.Classify.0200.norm", NON_SYSTEM_APP_UID + 1);
    std::vector<sptr<NotificationBundleOption>> bundles = { priorityBundle, normalBundle };
    std::vector<sptr<NotificationBundleOption>> priorityBundles;
    std::vector<sptr<NotificationBundleOption>> normalBundles;
    advancedNotificationService_->ClassifyExtensionBundles(bundles, priorityBundles, normalBundles);
    EXPECT_EQ(priorityBundles.size(), 1);
    EXPECT_EQ(normalBundles.size(), 1);
}

/**
 * @tc.number    : EnsureBundlesCanSubscribePriority_0100
 * @tc.name      : EnsureBundlesCanSubscribePriority
 * @tc.desc      : Test EnsureBundlesCanSubscribePriority returns false when bundle is nullptr
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribePriority_0100,
    Function | SmallTest | Level1)
{
    bool result = advancedNotificationService_->EnsureBundlesCanSubscribePriority(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.number    : EnsureBundlesCanSubscribePriority_0200
 * @tc.name      : EnsureBundlesCanSubscribePriority
 * @tc.desc      : Test EnsureBundlesCanSubscribePriority loads extension service and returns true
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, EnsureBundlesCanSubscribePriority_0200,
    Function | SmallTest | Level1)
{
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundle.EnsurePri.0200", NON_SYSTEM_APP_UID);
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    advancedNotificationService_->notificationExtensionHandler_ = nullptr;
    bool result = advancedNotificationService_->EnsureBundlesCanSubscribePriority(bundle);
    EXPECT_TRUE(result);
}

/**
 * @tc.number    : SubscribeExtensionServiceNotification_0100
 * @tc.name      : SubscribeExtensionServiceNotification
 * @tc.desc      : Test SubscribeExtensionServiceNotification returns -1 when extension not exist
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, SubscribeExtensionServiceNotification_0100,
    Function | SmallTest | Level1)
{
    advancedNotificationService_->notificationExtensionLoaded_.store(false);
    sptr<NotificationBundleOption> bundle =
        new NotificationBundleOption("bundle.SubscribeNoti.0100", NON_SYSTEM_APP_UID);
    int32_t result = advancedNotificationService_->SubscribeExtensionServiceNotification(bundle, 0);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.number    : ClassifyNormalSubscribers_0100
 * @tc.name      : ClassifyNormalSubscribers
 * @tc.desc      : Test ClassifyNormalSubscribers with bundles that have subscription bundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ClassifyNormalSubscribers_0100, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> subscriberBundle =
        new NotificationBundleOption("bundle.ClassifyNormal.0100", NON_SYSTEM_APP_UID);
    sptr<NotificationExtensionSubscriptionInfo> info =
        new NotificationExtensionSubscriptionInfo("addr", NotificationConstant::SubscribeType::BLUETOOTH);
    std::vector<sptr<NotificationExtensionSubscriptionInfo>> infos = { info };
    auto ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionInfos(subscriberBundle, infos);
    EXPECT_EQ(ret, ERR_OK);
    sptr<NotificationBundleOption> grantedBundle =
        new NotificationBundleOption("granted.ClassifyNormal.0100", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> grantedBundles = { grantedBundle };
    ret = NotificationPreferences::GetInstance()->SetExtensionSubscriptionBundles(subscriberBundle, grantedBundles);
    EXPECT_EQ(ret, ERR_OK);
    std::vector<sptr<NotificationBundleOption>> bundles = { subscriberBundle };
    std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> subscribedBundleInfos;
    advancedNotificationService_->ClassifyNormalSubscribers(bundles, subscribedBundleInfos);
    EXPECT_EQ(subscribedBundleInfos.size(), 1U);
    EXPECT_EQ(subscribedBundleInfos[0].first->GetBundleName(), "bundle.ClassifyNormal.0100");
}

/**
 * @tc.number    : ClassifyNormalSubscribers_0200
 * @tc.name      : ClassifyNormalSubscribers
 * @tc.desc      : Test ClassifyNormalSubscribers with bundles that have no subscription bundles
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ClassifyNormalSubscribers_0200, Function | SmallTest | Level1)
{
    MockIsNeedHapModuleInfos(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> subscriberBundle =
        new NotificationBundleOption("bundle.ClassifyNormal.0200", NON_SYSTEM_APP_UID);
    std::vector<sptr<NotificationBundleOption>> bundles = { subscriberBundle };
    std::vector<std::pair<sptr<NotificationBundleOption>,
        std::vector<sptr<NotificationBundleOption>>>> subscribedBundleInfos;
    advancedNotificationService_->ClassifyNormalSubscribers(bundles, subscribedBundleInfos);
    EXPECT_TRUE(subscribedBundleInfos.empty());
}
#endif

/**
 * @tc.number    : NotificationExtensionSubscribeNotification_0100
 * @tc.name      : NotificationExtensionSubscribeNotification
 * @tc.desc      : Test NotificationExtensionSubscribeNotification not system app
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribeNotification_0100,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    auto ret = advancedNotificationService_->NotificationExtensionSubscribeNotification(0);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : NotificationExtensionSubscribeNotification_0200
 * @tc.name      : NotificationExtensionSubscribeNotification
 * @tc.desc      : Test NotificationExtensionSubscribeNotification CanOpenSubscribeSettings fails
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribeNotification_0200,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    auto ret = advancedNotificationService_->NotificationExtensionSubscribeNotification(0);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : NotificationExtensionSubscribeNotification_0300
 * @tc.name      : NotificationExtensionSubscribeNotification
 * @tc.desc      : Test NotificationExtensionSubscribeNotification GenerateBundleOption returns nullptr
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribeNotification_0300,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNonBundleName(true);
    auto ret = advancedNotificationService_->NotificationExtensionSubscribeNotification(0);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
    MockIsNonBundleName(false);
}

/**
 * @tc.number    : NotificationExtensionSubscribeNotification_0400
 * @tc.name      : NotificationExtensionSubscribeNotification
 * @tc.desc      : Test NotificationExtensionSubscribeNotification without queue
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribeNotification_0400,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    advancedNotificationService_->notificationSvrQueue_.Reset();
    auto ret = advancedNotificationService_->NotificationExtensionSubscribeNotification(0);
    EXPECT_EQ(ret, (int)ERR_ANS_INNER_INVALID_PARAM);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : NotificationExtensionSubscribeNotification_0500
 * @tc.name      : NotificationExtensionSubscribeNotification
 * @tc.desc      : Test NotificationExtensionSubscribeNotification success path
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, NotificationExtensionSubscribeNotification_0500,
    Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    auto ret = advancedNotificationService_->NotificationExtensionSubscribeNotification(0);
    EXPECT_EQ(ret, ERR_OK);
    MockIsNeedHapModuleInfos(false);
}

/**
 * @tc.number    : ValidateExtensionBundleOption_0100
 * @tc.name      : ValidateExtensionBundleOption
 * @tc.desc      : Test ValidateExtensionBundleOption returns error when CheckBundleImplExtensionAbility fails
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ValidateExtensionBundleOption_0100,
    Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(false);
    sptr<NotificationBundleOption> bundleOption;
    auto result = advancedNotificationService_->ValidateExtensionBundleOption(bundleOption);
    EXPECT_EQ(result, ERR_ANS_INNER_NOT_IMPL_EXTENSIONABILITY);
    MockIsNeedHapModuleInfos(true);
}

/**
 * @tc.number    : ValidateExtensionBundleOption_0200
 * @tc.name      : ValidateExtensionBundleOption
 * @tc.desc      : Test ValidateExtensionBundleOption succeeds with valid extension ability
 */
HWTEST_F(AdvancedNotificationExtensionSubscriptionTest, ValidateExtensionBundleOption_0200,
    Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    MockIsNeedHapModuleInfos(true);
    sptr<NotificationBundleOption> bundleOption;
    auto result = advancedNotificationService_->ValidateExtensionBundleOption(bundleOption);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(bundleOption, nullptr);
}
}
}
