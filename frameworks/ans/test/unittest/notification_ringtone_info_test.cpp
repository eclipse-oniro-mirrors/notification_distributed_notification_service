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

#include "nlohmann/json.hpp"
#define private public
#define protected public
#include "notification_ringtone_info.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationRingtoneInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetRingtoneType_0001
 * @tc.desc: SetRingtoneType success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneType_0001, Level1)
{
    NotificationRingtoneInfo info;
    NotificationConstant::RingtoneType ringtoneType;
    using RT = NotificationConstant::RingtoneType;
    ringtoneType = RT::RINGTONE_TYPE_LOCAL;
    info.SetRingtoneType(ringtoneType);
    EXPECT_EQ(info.GetRingtoneType(), OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
}

/**
 * @tc.name: SetRingtoneType_0002
 * @tc.desc: SetRingtoneType success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneType_0002, Level1)
{
    NotificationRingtoneInfo info;
    NotificationConstant::RingtoneType ringtoneType;
    using RT = NotificationConstant::RingtoneType;
    ringtoneType = RT::RINGTONE_TYPE_BUTT;
    info.SetRingtoneType(ringtoneType);
    EXPECT_EQ(info.GetRingtoneType(), OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT);
}

/**
 * @tc.name: SetRingtoneType_0003
 * @tc.desc: SetRingtoneType success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneType_0003, Level1)
{
    NotificationRingtoneInfo info;
    NotificationConstant::RingtoneType ringtoneType;
    using RT = NotificationConstant::RingtoneType;
    ringtoneType = RT::RINGTONE_TYPE_ONLINE;
    info.SetRingtoneType(ringtoneType);
    EXPECT_EQ(info.GetRingtoneType(), OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
}

/**
 * @tc.name: SetRingtoneType_0004
 * @tc.desc: SetRingtoneType success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneType_0004, Level1)
{
    NotificationRingtoneInfo info;
    NotificationConstant::RingtoneType ringtoneType;
    using RT = NotificationConstant::RingtoneType;
    ringtoneType = RT::RINGTONE_TYPE_SYSTEM;
    info.SetRingtoneType(ringtoneType);
    EXPECT_EQ(info.GetRingtoneType(), OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
}

/**
 * @tc.name: SetRingtoneType_0005
 * @tc.desc: SetRingtoneType success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneType_0005, Level1)
{
    NotificationRingtoneInfo info;
    NotificationConstant::RingtoneType ringtoneType;
    using RT = NotificationConstant::RingtoneType;
    ringtoneType = RT::RINGTONE_TYPE_NONE;
    info.SetRingtoneType(ringtoneType);
    EXPECT_EQ(info.GetRingtoneType(), OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_NONE);
}

/**
 * @tc.name: SetRingtoneTitle_0001
 * @tc.desc: SetRingtoneTitle success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneTitle_0001, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneTitle = "ringtoneTitle";
    info.SetRingtoneTitle(ringtoneTitle);
    EXPECT_EQ(info.GetRingtoneTitle(), ringtoneTitle);
}

/**
 * @tc.name: SetRingtoneTitle_0002
 * @tc.desc: SetRingtoneTitle success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneTitle_0002, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneTitle = "";
    info.SetRingtoneTitle(ringtoneTitle);
    EXPECT_EQ(info.GetRingtoneTitle(), ringtoneTitle);
}

/**
 * @tc.name: SetRingtoneFileName_0001
 * @tc.desc: SetRingtoneFileName success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneFileName_0001, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneFileName = "ringtoneFileName";
    info.SetRingtoneFileName(ringtoneFileName);
    EXPECT_EQ(info.GetRingtoneFileName(), ringtoneFileName);
}

/**
 * @tc.name: SetRingtoneFileName_0002
 * @tc.desc: SetRingtoneFileName success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneFileName_0002, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneFileName = "";
    info.SetRingtoneFileName(ringtoneFileName);
    EXPECT_EQ(info.GetRingtoneFileName(), ringtoneFileName);
}

/**
 * @tc.name: ResetRingtone_0001
 * @tc.desc: After ResetRingtone, all fields should be default values
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, ResetRingtone_0001, Level1)
{
    NotificationRingtoneInfo info;

    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneTitle("title");
    info.SetRingtoneFileName("name");
    info.SetRingtoneUri("uri");

    info.ResetRingtone();

    EXPECT_EQ(static_cast<int>(info.GetRingtoneType()),
        static_cast<int>(OHOS::Notification::NotificationConstant::RingtoneType::RINGTONE_TYPE_BUTT));
    EXPECT_EQ(info.GetRingtoneTitle(), "");
    EXPECT_EQ(info.GetRingtoneFileName(), "");
    EXPECT_EQ(info.GetRingtoneUri(), "");
}

/**
 * @tc.name: SetRingtoneUri_0001
 * @tc.desc: SetRingtoneUri success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneUri_0001, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneUri = "uri";
    info.SetRingtoneUri(ringtoneUri);
    EXPECT_EQ(info.GetRingtoneUri(), ringtoneUri);
}

/**
 * @tc.name: SetRingtoneUri_0002
 * @tc.desc: SetRingtoneUri success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, SetRingtoneUri_0002, Level1)
{
    NotificationRingtoneInfo info;
    std::string ringtoneUri = "";
    info.SetRingtoneFileName(ringtoneUri);
    EXPECT_EQ(info.GetRingtoneUri(), ringtoneUri);
}

/**
 * @tc.name: Marshalling_0001
 * @tc.desc: Marshalling success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, Marshalling_0001, Level1)
{
    Parcel parcel;
    auto info = std::make_shared<NotificationRingtoneInfo>();
    EXPECT_EQ(info->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_0001
 * @tc.desc: Unmarshalling success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, Unmarshalling_0001, Level1)
{
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationRingtoneInfo> result =
        std::make_shared<NotificationRingtoneInfo>();

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_0001
 * @tc.desc: ReadFromParcel success
 * @tc.type: FUNC
 */
HWTEST_F(NotificationRingtoneInfoTest, ReadFromParcel_0001, Level1)
{
    Parcel parcel;
    
    int32_t typeValue = static_cast<int32_t>(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    parcel.WriteInt32(typeValue);

    parcel.WriteString("title");
    parcel.WriteString("name");
    parcel.WriteString("uri");

    NotificationRingtoneInfo info;
    bool result = info.ReadFromParcel(parcel);
    EXPECT_TRUE(result);

    EXPECT_EQ(static_cast<int>(info.GetRingtoneType()), typeValue);
    EXPECT_EQ(info.GetRingtoneTitle(), "title");
    EXPECT_EQ(info.GetRingtoneFileName(), "name");
    EXPECT_EQ(info.GetRingtoneUri(), "uri");
}

/**
 * @tc.name: Dump_0001
 * @tc.desc: Dump success
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationRingtoneInfoTest, Dump_0001, TestSize.Level1)
{
    NotificationRingtoneInfo info;
    info.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
    info.SetRingtoneTitle("title");
    info.SetRingtoneFileName("name");
    info.SetRingtoneUri("uri");

    std::string result = info.Dump();

    std::string ret =
        std::to_string(static_cast<int32_t>(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL)) +
        " title name uri";

    EXPECT_EQ(result, ret);
}
}
}