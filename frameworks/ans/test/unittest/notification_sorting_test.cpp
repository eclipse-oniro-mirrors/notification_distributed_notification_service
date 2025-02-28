/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define protected public
#include "notification_sorting_map.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationSortingTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingTest, Marshalling_00001, Function | SmallTest | Level1)
{
    NotificationSorting sorting;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationSorting>(sorting);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingTest, Marshalling_00002, Function | SmallTest | Level1)
{
    NotificationSorting sorting;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationSorting>(sorting);
    rrc->SetKey("");
    rrc->ReadFromParcel(parcel);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    NotificationSorting sorting;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    sorting.SetSlot(slot);
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationSorting> result =
    std::make_shared<NotificationSorting>(sorting);
    result->Marshalling(parcel);
    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationSortingTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationSorting sorting;
    sptr<NotificationSlot> slot = new (std::nothrow) NotificationSlot();
    sorting.SetSlot(slot);
    auto rrc = std::make_shared<NotificationSorting>(sorting);
    rrc->Marshalling(parcel);
    EXPECT_EQ(rrc->ReadFromParcel(parcel), true);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingTest, Dump_00001, Function | SmallTest | Level1)
{
    NotificationSorting sorting;
    Parcel parcel;
    std::string groupKeyOverride = "GroupKeyOverride";
    std::string key = "Key";
    int32_t importance = 10;
    uint64_t ranking = 20;
    int32_t visibleness =30;
    bool isDisplayBadge = false;
    bool isHiddenNotification = true;
    auto rrc = std::make_shared<NotificationSorting>(sorting);
    rrc->SetGroupKeyOverride(groupKeyOverride);
    rrc->SetKey(key);
    rrc->SetImportance(importance);
    rrc->SetRanking(ranking);
    rrc->SetVisiblenessOverride(visibleness);
    rrc->SetDisplayBadge(isDisplayBadge);
    rrc->SetHiddenNotification(isHiddenNotification);
    std::string ret = "NotificationSorting{ key = Key, ranking = 20, importance = 10, "
    "visiblenessOverride = 30, isDisplayBadge = false, isHiddenNotification = true, "
    "groupKeyOverride = GroupKeyOverride, slot = NotificationSlot{ id = OTHER, name "
    "= OTHER, description = , type = 3, level = 1, isBypassDnd = false, visibleness = "
    "3, sound = , isLightEnabled = false, lightColor = 0, isVibrate = false, vibration "
    "= , isShowBadge = true, enabled = true, slotFlags = 0, remindMode = 0 } }";
    EXPECT_EQ(rrc->Dump(), ret);
}
}
}
