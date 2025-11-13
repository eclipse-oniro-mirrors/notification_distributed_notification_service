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
#include "notification_reminder_info.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationReminderInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: NotificationReminderInfo_00001
 * @tc.desc: Test NotificationReminderInfo.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationReminderInfoTest, NotificationReminderInfo_00001, Function | SmallTest | Level1)
{
    std::string bundleName = "BundleName";
    int32_t uid = 10;
    auto bundle = std::make_shared<NotificationBundleOption>(bundleName, uid);
    auto rrc = std::make_shared<NotificationReminderInfo>();
    rrc->SetBundleOption(*bundle);
    EXPECT_EQ(rrc->GetBundleOption().GetBundleName(), bundleName);
    uint32_t flags = 59;
    rrc->SetReminderFlags(flags);
    EXPECT_EQ(rrc->GetReminderFlags(), flags);
    bool enable = true;
    rrc->SetSilentReminderEnabled(enable);
    EXPECT_EQ(rrc->GetSilentReminderEnabled(), enable);
    string dumpstr = rrc->Dump();

    Parcel parcel;
    EXPECT_EQ(rrc->Marshalling(parcel), true);

    bool unmarshalling = true;
    if (nullptr != rrc) {
        if (rrc->Unmarshalling(parcel) != nullptr) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, false);

    nlohmann::json jsonObject;
    EXPECT_TRUE(rrc->ToJson(jsonObject));
    auto *rrcNew = rrc->FromJson(jsonObject);
    EXPECT_EQ(rrcNew->GetBundleOption().GetBundleName(), rrc->GetBundleOption().GetBundleName());
}
} // namespace Notification
} // namespace OHOS
