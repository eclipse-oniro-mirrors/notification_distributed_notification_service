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

#include "gtest/gtest.h"

#define private public
#include "ans_inner_errors.h"
#include "distributed_data_define.h"
#include "distributed_extension_service.h"
#include "distributed_device_manager.h"
#include "mock_device_manager_impl.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;
using namespace DistributedHardware;

extern void MockIsVerfyPermisson(bool isVerify);
extern void MockGetTokenTypeFlag(ATokenTypeEnum mockRet);
extern void MockIsSystemApp(bool isSystemApp);
extern void MockIsAtomicServiceByFullTokenID(bool isAtomicService);

class NotificationRingtoneServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void NotificationRingtoneServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    GTEST_LOG_(INFO) << "SetUp end";
}

void NotificationRingtoneServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}

/**
 * @tc.name: set notification ringtone
 * @tc.desc: Test invalid param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneServiceTest, setRingtone_00001, Function | SmallTest | Level1)
{
    // init extension conifg.
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption();
    sptr<NotificationRingtoneInfo> ringtone = new NotificationRingtoneInfo();
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    auto result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_NON_SYSTEM_APP);

    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_NON_SYSTEM_APP);

    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, nullptr);
    ASSERT_EQ(result, (int32_t)ERR_ANS_INVALID_PARAM);

    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_INVALID_PARAM);

    ringtone->SetRingtoneUri("test_uri");
    ringtone->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_INVALID_PARAM);

    bundle->SetUid(20020201);
    bundle->SetBundleName("com.ohos.demo");
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_OK);
}

/**
 * @tc.name: get notification ringtone
 * @tc.desc: Test invalid param
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneServiceTest, getRingtone_00001, Function | SmallTest | Level1)
{
    // init extension conifg.
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption();
    sptr<NotificationRingtoneInfo> ringtone = new NotificationRingtoneInfo();
    MockIsSystemApp(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    auto result = AdvancedNotificationService::GetInstance().GetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_NON_SYSTEM_APP);

    MockIsVerfyPermisson(false);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    result = AdvancedNotificationService::GetInstance().GetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_PERMISSION_DENIED);

    MockIsSystemApp(true);
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP);
    result = AdvancedNotificationService::GetInstance().GetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_PERMISSION_DENIED);

    MockIsVerfyPermisson(true);
    result = AdvancedNotificationService::GetInstance().GetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_ANS_INVALID_PARAM);

    bundle->SetUid(20020200);
    bundle->SetBundleName("com.ohos.demo");
    sptr<NotificationRingtoneInfo> setRingtone = new NotificationRingtoneInfo(
        NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE, "title", "name", "uri");
    result = AdvancedNotificationService::GetInstance().SetRingtoneInfoByBundle(bundle, setRingtone);
    ASSERT_EQ(result, (int32_t)ERR_OK);

    result = AdvancedNotificationService::GetInstance().GetRingtoneInfoByBundle(bundle, ringtone);
    ASSERT_EQ(result, (int32_t)ERR_OK);
}
}
}
