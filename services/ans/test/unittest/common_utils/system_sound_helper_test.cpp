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

#include <gtest/gtest.h>

#define private public

#include "system_sound_helper.h"
#include "notification_ringtone_info.h"

#undef private

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class SystemSoundHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: GetInstance_00001
 * @tc.desc: Test GetInstance creates instance only once.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, GetInstance_00001, Function | SmallTest | Level1)
{
    SystemSoundHelper::instance_ = nullptr;
    auto instance = SystemSoundHelper::GetInstance();
    EXPECT_NE(instance, nullptr);
    auto instance2 = SystemSoundHelper::GetInstance();
    EXPECT_EQ(instance, instance2);
}

/**
 * @tc.name: RemoveCustomizedTone_00001
 * @tc.desc: Test RemoveCustomizedTone with empty uri.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::string uri = "";

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
}

/**
 * @tc.name: RemoveCustomizedTone_00002
 * @tc.desc: Test RemoveCustomizedTone with valid uri.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_00002, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::string uri = "/test/path/ringtone.mp3";

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
}

/**
 * @tc.name: RemoveCustomizedTone_00003
 * @tc.desc: Test RemoveCustomizedTone with long uri.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_00003, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::string uri = "/very/long/path/to/ringtone/file/that/should/be/handled/test.mp3";

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
}

/**
 * @tc.name: RemoveCustomizedTone_00004
 * @tc.desc: Test RemoveCustomizedTone with special characters in uri.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_00004, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::string uri = "/test/path with spaces/ringtone.mp3";

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00001
 * @tc.desc: Test RemoveCustomizedTone with nullptr ringtoneInfo.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = nullptr;

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00002
 * @tc.desc: Test RemoveCustomizedTone with RINGTONE_TYPE_LOCAL.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00002, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneUri("/test/local/ringtone.mp3");

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00003
 * @tc.desc: Test RemoveCustomizedTone with RINGTONE_TYPE_ONLINE.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00003, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo->SetRingtoneUri("/test/online/ringtone.mp3");

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00004
 * @tc.desc: Test RemoveCustomizedTone with RINGTONE_TYPE_DEFAULT.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00004, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00005
 * @tc.desc: Test RemoveCustomizedTone with RINGTONE_TYPE_SIM_CARD_1.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00005, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_00006
 * @tc.desc: Test RemoveCustomizedTone with RINGTONE_TYPE_SIM_CARD_2.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_00006, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTones_00001
 * @tc.desc: Test RemoveCustomizedTones with empty vector.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00002
 * @tc.desc: Test RemoveCustomizedTones with single local ringtone.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00002, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo.SetRingtoneUri("/test/local1.mp3");
    ringtoneInfos.push_back(ringtoneInfo);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00003
 * @tc.desc: Test RemoveCustomizedTones with single online ringtone.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00003, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo.SetRingtoneUri("/test/online1.mp3");
    ringtoneInfos.push_back(ringtoneInfo);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00004
 * @tc.desc: Test RemoveCustomizedTones with multiple mixed ringtones.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00004, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo1;
    ringtoneInfo1.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo1.SetRingtoneUri("/test/local1.mp3");
    ringtoneInfos.push_back(ringtoneInfo1);
    
    NotificationRingtoneInfo ringtoneInfo2;
    ringtoneInfo2.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo2.SetRingtoneUri("/test/online1.mp3");
    ringtoneInfos.push_back(ringtoneInfo2);
    
    NotificationRingtoneInfo ringtoneInfo3;
    ringtoneInfo3.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
    ringtoneInfo3.SetRingtoneUri("/test/default.mp3");
    ringtoneInfos.push_back(ringtoneInfo3);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00005
 * @tc.desc: Test RemoveCustomizedTones with only default ringtones.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00005, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo1;
    ringtoneInfo1.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
    ringtoneInfo1.SetRingtoneUri("/test/default1.mp3");
    ringtoneInfos.push_back(ringtoneInfo1);
    
    NotificationRingtoneInfo ringtoneInfo2;
    ringtoneInfo2.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo2.SetRingtoneUri("/test/sim1.mp3");
    ringtoneInfos.push_back(ringtoneInfo2);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00006
 * @tc.desc: Test RemoveCustomizedTones with many local ringtones.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00006, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    for (int i = 0; i < 10; i++) {
        NotificationRingtoneInfo ringtoneInfo;
        ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
        ringtoneInfo.SetRingtoneUri("/test/local" + std::to_string(i) + ".mp3");
        ringtoneInfos.push_back(ringtoneInfo);
    }

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00007
 * @tc.desc: Test RemoveCustomizedTones with many online ringtones.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00007, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    for (int i = 0; i < 10; i++) {
        NotificationRingtoneInfo ringtoneInfo;
        ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
        ringtoneInfo.SetRingtoneUri("/test/online" + std::to_string(i) + ".mp3");
        ringtoneInfos.push_back(ringtoneInfo);
    }

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00008
 * @tc.desc: Test RemoveCustomizedTones with empty uri in local ringtone.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00008, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo.SetRingtoneUri("");
    ringtoneInfos.push_back(ringtoneInfo);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00009
 * @tc.desc: Test RemoveCustomizedTones with empty uri in online ringtone.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00009, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo.SetRingtoneUri("");
    ringtoneInfos.push_back(ringtoneInfo);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: RemoveCustomizedTones_00010
 * @tc.desc: Test RemoveCustomizedTones with mixed empty and valid uris.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_00010, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo1;
    ringtoneInfo1.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo1.SetRingtoneUri("");
    ringtoneInfos.push_back(ringtoneInfo1);
    
    NotificationRingtoneInfo ringtoneInfo2;
    ringtoneInfo2.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo2.SetRingtoneUri("/test/valid.mp3");
    ringtoneInfos.push_back(ringtoneInfo2);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: NotificationRingtoneInfo_00001
 * @tc.desc: Test NotificationRingtoneInfo basic functionality.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, NotificationRingtoneInfo_00001, Function | SmallTest | Level1)
{
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo.SetRingtoneUri("/test/ringtone.mp3");

    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    EXPECT_EQ(ringtoneInfo.GetRingtoneUri(), "/test/ringtone.mp3");
}

/**
 * @tc.name: NotificationRingtoneInfo_00002
 * @tc.desc: Test NotificationRingtoneInfo with all ringtone types.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, NotificationRingtoneInfo_00002, Function | SmallTest | Level1)
{
    NotificationRingtoneInfo ringtoneInfo;
    
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
    
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    EXPECT_EQ(ringtoneInfo.GetRingtoneType(), NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
}

/**
 * @tc.name: RemoveCustomizedTone_MultipleCalls_00001
 * @tc.desc: Test multiple calls to RemoveCustomizedTone with same uri.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_MultipleCalls_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::string uri = "/test/ringtone.mp3";

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
    EXPECT_NO_THROW(instance->RemoveCustomizedTone(uri));
}

/**
 * @tc.name: RemoveCustomizedTones_MultipleCalls_00001
 * @tc.desc: Test multiple calls to RemoveCustomizedTones with same vector.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_MultipleCalls_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo;
    ringtoneInfo.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo.SetRingtoneUri("/test/ringtone.mp3");
    ringtoneInfos.push_back(ringtoneInfo);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}

/**
 * @tc.name: SystemSoundHelper_Instance_00001
 * @tc.desc: Test instance_ static member initialization.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, SystemSoundHelper_Instance_00001, Function | SmallTest | Level1)
{
    SystemSoundHelper::instance_ = nullptr;
    auto instance = SystemSoundHelper::GetInstance();
    EXPECT_NE(SystemSoundHelper::instance_, nullptr);
}

/**
 * @tc.name: RemoveCustomizedTone_RingtoneInfo_WithEmptyUri_00001
 * @tc.desc: Test RemoveCustomizedTone with ringtoneInfo having empty uri but valid type.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTone_RingtoneInfo_WithEmptyUri_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    sptr<NotificationRingtoneInfo> ringtoneInfo = new NotificationRingtoneInfo();
    ringtoneInfo->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo->SetRingtoneUri("");

    EXPECT_NO_THROW(instance->RemoveCustomizedTone(ringtoneInfo));
}

/**
 * @tc.name: RemoveCustomizedTones_WithMixedTypesAndEmptyUris_00001
 * @tc.desc: Test RemoveCustomizedTones with various combinations.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(SystemSoundHelperTest, RemoveCustomizedTones_WithMixedTypesAndEmptyUris_00001, Function | SmallTest | Level1)
{
    auto instance = SystemSoundHelper::GetInstance();
    std::vector<NotificationRingtoneInfo> ringtoneInfos;
    
    NotificationRingtoneInfo ringtoneInfo1;
    ringtoneInfo1.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo1.SetRingtoneUri("/valid1.mp3");
    ringtoneInfos.push_back(ringtoneInfo1);
    
    NotificationRingtoneInfo ringtoneInfo2;
    ringtoneInfo2.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    ringtoneInfo2.SetRingtoneUri("");
    ringtoneInfos.push_back(ringtoneInfo2);
    
    NotificationRingtoneInfo ringtoneInfo3;
    ringtoneInfo3.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
    ringtoneInfo3.SetRingtoneUri("/valid2.mp3");
    ringtoneInfos.push_back(ringtoneInfo3);
    
    NotificationRingtoneInfo ringtoneInfo4;
    ringtoneInfo4.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
    ringtoneInfo4.SetRingtoneUri("/default.mp3");
    ringtoneInfos.push_back(ringtoneInfo4);

    EXPECT_NO_THROW(instance->RemoveCustomizedTones(ringtoneInfos));
}
}  // namespace Notification
}  // namespace OHOS