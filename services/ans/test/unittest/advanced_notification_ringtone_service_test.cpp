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

#include "errors.h"
#include "notification_content.h"
#include "notification_record.h"
#include "notification_request.h"
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

#include "gtest/gtest.h"
#include <vector>

#define private public

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "ans_log_wrapper.h"
#include "ans_notification.h"
#include "ans_result_data_synchronizer.h"
#include "ans_ut_constant.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "notification_analytics_util.h"
#include "iremote_object.h"
#include "mock_ipc_skeleton.h"
#include "notification_preferences.h"
#include "notification_subscriber.h"
#include "notification_subscriber_manager.h"
#include "mock_push_callback_stub.h"
#include "os_account_manager_helper.h"
#include "system_event_observer.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "bundle_manager_helper.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {
extern void MockIsVerfyPermisson(bool isVerify);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);

class AdvancedNotificationRingToneServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationRingToneServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationRingToneServiceTest::SetUpTestCase() {}

void AdvancedNotificationRingToneServiceTest::TearDownTestCase() {}

void AdvancedNotificationRingToneServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    NotificationPreferences::GetInstance()->ClearNotificationInRestoreFactorySettings();
    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();
    sptr<AnsResultDataSynchronizerImpl> synchronizer = new (std::nothrow) AnsResultDataSynchronizerImpl();
    auto ret = advancedNotificationService_->CancelAll("",
        iface_cast<IAnsResultDataSynchronizer>(synchronizer->AsObject()));
    if (ret == ERR_OK) {
        synchronizer->Wait();
    }
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockIsSystemApp(true);
    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationRingToneServiceTest::TearDown()
{
    delete advancedNotificationService_;
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.number    : SetRingtoneInfoByBundle_00001
 * @tc.name      : SetRingtoneInfoByBundle
 * @tc.desc      : Test SetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, SetRingtoneInfoByBundle_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    auto ret = advancedNotificationService_->SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : SetRingtoneInfoByBundle_00002
 * @tc.name      : SetRingtoneInfoByBundle
 * @tc.desc      : Test SetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, SetRingtoneInfoByBundle_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    auto ret = advancedNotificationService_->SetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : SetRingtoneInfoByBundle_00003
 * @tc.name      : SetRingtoneInfoByBundle
 * @tc.desc      : Test SetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, SetRingtoneInfoByBundle_00003, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneFileName("fileName");
    ringtoneInfo->SetRingtoneUri("uri");
    ASSERT_EQ(advancedNotificationService_->SetRingtoneInfoByBundle(bundleOption, ringtoneInfo), ERR_OK);
}

/**
 * @tc.number    : SetRingtoneInfoByBundle_00004
 * @tc.name      : SetRingtoneInfoByBundle
 * @tc.desc      : Test SetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, SetRingtoneInfoByBundle_00004, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = nullptr;
    sptr<NotificationRingtoneInfo> ringtoneInfo = nullptr;
    ASSERT_EQ(advancedNotificationService_->SetRingtoneInfoByBundle(bundleOption, ringtoneInfo),
        ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : GetRingtoneInfoByBundle_00001
 * @tc.name      : GetRingtoneInfoByBundle
 * @tc.desc      : Test GetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, GetRingtoneInfoByBundle_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    auto ret = advancedNotificationService_->GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INNER_NON_SYSTEM_APP);
}

/**
 * @tc.number    : GetRingtoneInfoByBundle_00002
 * @tc.name      : GetRingtoneInfoByBundle
 * @tc.desc      : Test GetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, GetRingtoneInfoByBundle_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    auto ret = advancedNotificationService_->GetRingtoneInfoByBundle(bundleOption, ringtoneInfo);
    ASSERT_EQ(ret, ERR_ANS_INNER_PERMISSION_DENIED);
}

/**
 * @tc.number    : GetRingtoneInfoByBundle_00003
 * @tc.name      : GetRingtoneInfoByBundle
 * @tc.desc      : Test GetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, GetRingtoneInfoByBundle_00003, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption();
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(ringtoneInfo, nullptr);
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ASSERT_EQ(advancedNotificationService_->GetRingtoneInfoByBundle(bundleOption, ringtoneInfo),
        ERR_ANS_INNER_INVALID_PARAM);
}

/**
 * @tc.number    : GetRingtoneInfoByBundle_00004
 * @tc.name      : GetRingtoneInfoByBundle
 * @tc.desc      : Test GetRingtoneInfoByBundle
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, GetRingtoneInfoByBundle_00004, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    sptr<NotificationBundleOption> bundleOption = new (std::nothrow) NotificationBundleOption("bundle", 1);
    ASSERT_NE(bundleOption, nullptr);
    sptr<NotificationRingtoneInfo> setRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    setRingtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    setRingtoneInfo->SetRingtoneFileName("fileName");
    setRingtoneInfo->SetRingtoneUri("uri");
    ASSERT_EQ(advancedNotificationService_->SetRingtoneInfoByBundle(bundleOption, setRingtoneInfo), ERR_OK);
    sptr<NotificationRingtoneInfo> getRingtoneInfo = new (std::nothrow) NotificationRingtoneInfo();
    ASSERT_NE(getRingtoneInfo, nullptr);
    ASSERT_EQ(advancedNotificationService_->GetRingtoneInfoByBundle(bundleOption, getRingtoneInfo), ERR_OK);
}

/**
 * @tc.number    : FilterValidRingtoneUris_00001
 * @tc.name      : FilterValidRingtoneUris
 * @tc.desc      : Test FilterValidRingtoneUris skips ringtone with empty uri.
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, FilterValidRingtoneUris_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneUri("");
    std::vector<NotificationRingtoneInfo> infos = { info };

    auto result = advancedNotificationService_->FilterValidRingtoneUris(infos);
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.number    : FilterValidRingtoneUris_00002
 * @tc.name      : FilterValidRingtoneUris
 * @tc.desc      : Test FilterValidRingtoneUris skips ringtone uri containing path traversal ".."
 *                 (equivalent guard branch of ClearRingtoneByApplication line 142).
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, FilterValidRingtoneUris_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneUri("../data/uri");
    std::vector<NotificationRingtoneInfo> infos = { info };

    auto result = advancedNotificationService_->FilterValidRingtoneUris(infos);
    EXPECT_EQ(result.size(), 0);
}

/**
 * @tc.number    : FilterValidRingtoneUris_00003
 * @tc.name      : FilterValidRingtoneUris
 * @tc.desc      : Test FilterValidRingtoneUris keeps valid ringtone uri.
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, FilterValidRingtoneUris_00003, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneUri("/data/valid/uri");
    std::vector<NotificationRingtoneInfo> infos = { info };

    auto result = advancedNotificationService_->FilterValidRingtoneUris(infos);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].GetRingtoneUri(), "/data/valid/uri");
}

/**
 * @tc.number    : FilterValidRingtoneUris_00004
 * @tc.name      : FilterValidRingtoneUris
 * @tc.desc      : Test FilterValidRingtoneUris filters mixed uris and keeps only valid ones.
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, FilterValidRingtoneUris_00004, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    NotificationRingtoneInfo emptyInfo;
    emptyInfo.SetRingtoneUri("");
    NotificationRingtoneInfo traversalInfo;
    traversalInfo.SetRingtoneUri("../etc/uri");
    NotificationRingtoneInfo validInfo;
    validInfo.SetRingtoneUri("/data/service/el2/100/uri");
    std::vector<NotificationRingtoneInfo> infos = { emptyInfo, traversalInfo, validInfo };

    auto result = advancedNotificationService_->FilterValidRingtoneUris(infos);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].GetRingtoneUri(), "/data/service/el2/100/uri");
}

/**
 * @tc.number    : ClearRingtoneByApplication_00001
 * @tc.name      : ClearRingtoneByApplication
 * @tc.desc      : Test ClearRingtoneByApplication returns early with empty cloneRingtoneInfos.
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, ClearRingtoneByApplication_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    std::vector<NotificationRingtoneInfo> emptyInfos;

    advancedNotificationService_->ClearRingtoneByApplication(100, emptyInfos);
    EXPECT_TRUE(emptyInfos.empty());
}

/**
 * @tc.number    : ClearOverTimeRingToneInfo_00001
 * @tc.name      : ClearOverTimeRingToneInfo
 * @tc.desc      : Test ClearOverTimeRingToneInfo skips everything when clone time is zero (never cloned).
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, ClearOverTimeRingToneInfo_00001, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    // default state: no clone timestamp seeded, :172 condition is false, nothing runs
    advancedNotificationService_->ClearOverTimeRingToneInfo();
    EXPECT_EQ(NotificationPreferences::GetInstance()->GetCloneTimeStamp(), 0);
}

/**
 * @tc.number    : ClearOverTimeRingToneInfo_00002
 * @tc.name      : ClearOverTimeRingToneInfo
 * @tc.desc      : Test ClearOverTimeRingToneInfo clears the seeded overtime clone timestamp:
 *                 the async task resets the timestamp to 0 after running the clear flow.
 */
HWTEST_F(AdvancedNotificationRingToneServiceTest, ClearOverTimeRingToneInfo_00002, Function | SmallTest | Level1)
{
    ASSERT_NE(advancedNotificationService_, nullptr);
    // seed a timestamp older than MAX_CLONE_TIME (7 days) for the mocked foreground user (100)
    constexpr int64_t OVERTIME_MS = 8 * 24 * 60 * 60 * 1000; // 8 days in milliseconds
    int64_t overtimeStamp = NotificationAnalyticsUtil::GetCurrentTime() - OVERTIME_MS;
    NotificationPreferences::GetInstance()->SetCloneTimeStamp(100, overtimeStamp);
    ASSERT_NE(NotificationPreferences::GetInstance()->GetCloneTimeStamp(), 0);

    advancedNotificationService_->ClearOverTimeRingToneInfo();
    // wait for the async ffrt task; it resets the timestamp to 0 at the end (:192)
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(NotificationPreferences::GetInstance()->GetCloneTimeStamp(), 0);
}
}  // namespace Notification
}  // namespace OHOS
