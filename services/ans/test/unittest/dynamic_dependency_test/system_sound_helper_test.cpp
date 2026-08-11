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

#include <gtest/gtest.h>
#include <memory>
#include <vector>
#include <string>

#define private public

#include "system_sound_helper.h"
#include "notification_ringtone_info.h"
#include "notification_constant.h"

#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Notification;

namespace OHOS {
namespace Notification {

class SystemSoundHelperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SystemSoundHelperTest::SetUpTestCase() {}

void SystemSoundHelperTest::TearDownTestCase() {}

void SystemSoundHelperTest::SetUp()
{
    auto helper = SystemSoundHelper::GetInstance();
    if (helper->soundHelperQueue_ == nullptr) {
        helper->soundHelperQueue_ = std::make_shared<ffrt::queue>("SoundHelper");
    }
}

void SystemSoundHelperTest::TearDown()
{
    SystemSoundHelper::GetInstance()->WaitForFfrtQueue(true);
}

HWTEST_F(SystemSoundHelperTest, GetInstance_QueueInitialized_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_NullQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    helper->soundHelperQueue_ = nullptr;
    helper->RemoveCustomizedTone("test_uri");
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_EmptyUri_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->RemoveCustomizedTone(std::string(""));
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_NullRingtoneInfo_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    sptr<NotificationRingtoneInfo> ringtoneInfo = nullptr;
    helper->RemoveCustomizedTone(ringtoneInfo);
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_NullQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    helper->soundHelperQueue_ = nullptr;
    std::vector<NotificationRingtoneInfo> infos;
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneUri("test_uri");
    infos.push_back(info);
    helper->RemoveCustomizedTones(infos);
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_EmptyInput_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    std::vector<NotificationRingtoneInfo> infos;
    helper->RemoveCustomizedTones(infos);
}

HWTEST_F(SystemSoundHelperTest, ResetQueue_NullQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    helper->soundHelperQueue_ = nullptr;
    helper->WaitForFfrtQueue(true);
}

HWTEST_F(SystemSoundHelperTest, ResetQueue_Normal_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->WaitForFfrtQueue(true);
    EXPECT_EQ(helper->soundHelperQueue_, nullptr);
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_SubmitToQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    ASSERT_NE(helper->soundHelperQueue_, nullptr);
    helper->RemoveCustomizedTone("test_uri_submit");
    helper->WaitForFfrtQueue();
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->WaitForFfrtQueue(true);
    EXPECT_EQ(helper->soundHelperQueue_, nullptr);
}

HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_SubmitToQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    ASSERT_NE(helper->soundHelperQueue_, nullptr);
    std::vector<NotificationRingtoneInfo> infos;
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneUri("test_uri_list");
    infos.push_back(info);
    helper->RemoveCustomizedTones(infos);
    helper->WaitForFfrtQueue();
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->WaitForFfrtQueue(true);
    EXPECT_EQ(helper->soundHelperQueue_, nullptr);
}

HWTEST_F(SystemSoundHelperTest, WaitForFfrtQueue_NullQueue_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    helper->soundHelperQueue_ = nullptr;
    helper->WaitForFfrtQueue();
}

HWTEST_F(SystemSoundHelperTest, WaitForFfrtQueue_Normal_00001, Function | SmallTest | Level1)
{
    auto helper = SystemSoundHelper::GetInstance();
    ASSERT_NE(helper, nullptr);
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->RemoveCustomizedTone("test_uri_wait");
    helper->WaitForFfrtQueue();
    EXPECT_NE(helper->soundHelperQueue_, nullptr);
    helper->WaitForFfrtQueue(true);
    EXPECT_EQ(helper->soundHelperQueue_, nullptr);
}
}  // namespace Notification
}  // namespace OHOS
