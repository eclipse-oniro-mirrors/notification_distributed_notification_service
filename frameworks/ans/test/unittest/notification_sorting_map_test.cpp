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
class NotificationSortingMapTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetKey_00001
 * @tc.desc: Test SetKey parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingMapTest, SetKey_00001, Function | SmallTest | Level1)
{
    std::vector<NotificationSorting> sortingList;
    std::string key = "Key";
    auto rrc = std::make_shared<NotificationSortingMap>(sortingList);
    NotificationSorting sorting;
    rrc->SetNotificationSorting(sortingList);
    EXPECT_EQ(rrc->GetNotificationSorting(key, sorting), false);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingMapTest, Marshalling_00001, Function | SmallTest | Level1)
{
    std::vector<NotificationSorting> sortingList;
    Parcel parcel;
    auto rrc = std::make_shared<NotificationSortingMap>(sortingList);
    EXPECT_EQ(rrc->Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingMapTest, Unmarshalling_001, Function | SmallTest | Level1)
{
    std::vector<NotificationSorting> sortingList;
    bool unmarshalling = true;
    Parcel parcel;
    std::shared_ptr<NotificationSortingMap> result =
    std::make_shared<NotificationSortingMap>(sortingList);

    if (nullptr != result) {
        if (nullptr == result->Unmarshalling(parcel)) {
            unmarshalling = false;
        }
    }
    EXPECT_EQ(unmarshalling, true);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationSortingMapTest, Dump_00001, Function | SmallTest | Level1)
{
    std::vector<NotificationSorting> sortingList;
    std::string key = "Key";
    auto rrc = std::make_shared<NotificationSortingMap>(sortingList);
    rrc->SetKey(key);
    std::string ret = "NotificationSortingMap{ sortedkey = [Key, ] }";
    EXPECT_EQ(rrc->Dump(), ret);
}
}
}