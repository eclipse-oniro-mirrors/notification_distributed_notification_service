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
#include <string>
#include "int_wrapper.h"
#include "notification_statistics.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationStatisticsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetLastTime_00001
 * @tc.desc: Test GetLastTime of NotificationStatistics.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, GetLastTime_00001, Function | SmallTest | Level0)
{
    NotificationStatistics statistics;
    EXPECT_EQ(statistics.GetLastTime(), 0);
    statistics.SetLastTime(1000);
    EXPECT_EQ(statistics.GetLastTime(), 1000);
}

/**
 * @tc.name: GetBundleOption_00001
 * @tc.desc: Test GetBundleOption of NotificationStatistics.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, GetBundleOption_00001, Function | SmallTest | Level0)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    NotificationBundleOption result = statistics.GetBundleOption();
    EXPECT_EQ(result.GetBundleName(), "test.bundle");
    EXPECT_EQ(result.GetUid(), 100);
}

/**
 * @tc.name: GetRecentCount_00001
 * @tc.desc: Test GetRecentCount of NotificationStatistics.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, GetRecentCount_00001, Function | SmallTest | Level0)
{
    NotificationStatistics statistics;
    EXPECT_EQ(statistics.GetRecentCount(), 0);
    statistics.SetRecentCount(1000);
    EXPECT_EQ(statistics.GetRecentCount(), 1000);
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test GetBundleOption of NotificationStatistics.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, Dump_00001, Function | SmallTest | Level0)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    EXPECT_EQ(statistics.Dump(), "Statistics{ bundle = NotificationBundleOption{"
    " bundleName = test.bundle, uid = 100, instanceKey = 0, appIndex = -1 }, lastTime = 0, recentCount = 0 }");
}

/**
 * @tc.name: JsonConvert_00001
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, JsonConvert_00001, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    nlohmann::json jsonObject;
    EXPECT_TRUE(statistics.ToJson(jsonObject));
    auto *rrcNew = statistics.FromJson(jsonObject);
    ASSERT_NE(rrcNew, nullptr);
    EXPECT_EQ(rrcNew->GetBundleOption().GetBundleName(), statistics.GetBundleOption().GetBundleName());
    delete rrcNew;
}

/**
 * @tc.name: JsonConvert_00002
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, JsonConvert_00002, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption = {};
    statistics.SetBundleOption(bundleOption);
    nlohmann::json jsonObject;
    EXPECT_TRUE(statistics.ToJson(jsonObject));
}

/**
 * @tc.name: JsonConvert_00003
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, JsonConvert_00003, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    nlohmann::json jsonObject;
    EXPECT_TRUE(statistics.ToJson(jsonObject));
    nlohmann::json jsonObject1 = nlohmann::json{"testJson"};
    auto *rrcNew = statistics.FromJson(jsonObject1);
    EXPECT_EQ(rrcNew, nullptr);
}

/**
 * @tc.name: JsonConvert_00004
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, JsonConvert_00004, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    nlohmann::json jsonObject;
    EXPECT_TRUE(statistics.ToJson(jsonObject));
    jsonObject = {1, 2, 3};
    auto *rrcNew = statistics.FromJson(jsonObject);
    EXPECT_EQ(rrcNew, nullptr);
}

/**
 * @tc.name: JsonConvert_00005
 * @tc.desc: Test json convert
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, JsonConvert_00005, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    nlohmann::json jsonObject;
    EXPECT_TRUE(statistics.ToJson(jsonObject));
    jsonObject = {};
    jsonObject["lastTime"] = 10;
    auto *rrc01 = statistics.FromJson(jsonObject);
    ASSERT_NE(rrc01, nullptr);
    EXPECT_EQ(rrc01->GetLastTime(), 10);
    jsonObject = {};
    jsonObject["recentCount"] = 100;
    auto *rrc02 = statistics.FromJson(jsonObject);
    ASSERT_NE(rrc02, nullptr);
    EXPECT_EQ(rrc02->GetRecentCount(), 100);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, Marshalling_00001, Function | SmallTest | Level0)
{
    NotificationStatistics statistics;
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("test.bundle");
    bundleOption.SetUid(100);
    statistics.SetBundleOption(bundleOption);
    Parcel parcel;
    EXPECT_EQ(statistics.Marshalling(parcel), true);
    auto ptr = statistics.Unmarshalling(parcel);
    EXPECT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->GetBundleOption().GetBundleName(), statistics.GetBundleOption().GetBundleName());
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(NotificationStatisticsTest, Marshalling_00002, Function | SmallTest | Level1)
{
    NotificationStatistics statistics;
    Parcel parcel;
    auto ptr = statistics.Unmarshalling(parcel);
    EXPECT_EQ(ptr, nullptr);
}
}
}
