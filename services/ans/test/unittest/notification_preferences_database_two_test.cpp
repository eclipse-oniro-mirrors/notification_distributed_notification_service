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

#define private public
#include <gtest/gtest.h>

#define private public
#define protected public
#include "notification_preferences_database.h"
#undef private
#undef protected

extern void MockIsOsAccountExists(bool exists);
extern void MockQueryForgroundOsAccountId(bool mockRet, uint8_t mockCase);

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesDatabaseTwoTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void TearDown() {};

    std::unique_ptr<NotificationPreferencesDatabase> preferncesDB_ =
        std::make_unique<NotificationPreferencesDatabase>();
};

HWTEST_F(NotificationPreferencesDatabaseTwoTest, GetHashCodeRule_0300, TestSize.Level1)
{
    std::shared_ptr<NotificationPreferencesDatabase> notificationPreferencesDatabase =
        std::make_shared<NotificationPreferencesDatabase>();
    int32_t uid = 100;
    int32_t userId = -1;
    auto res = notificationPreferencesDatabase->GetHashCodeRule(uid, userId);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: HandleDataBaseMap_0300
 * @tc.desc: test HandleDataBaseMap.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTwoTest, HandleDataBaseMap_0300, TestSize.Level1)
{
    MockQueryForgroundOsAccountId(false, 0);
    NotificationBundleOption bundle1 = NotificationBundleOption("ohos.example.demo", 10000);
    NotificationBundleOption bundle2 = NotificationBundleOption("ohos.example.demo", 10001);
    std::unordered_map<std::string, std::string> datas;
    std::vector<NotificationBundleOption> bundleOption;
    bundleOption.push_back(bundle1);
    bundleOption.push_back(bundle2);
    auto ret = preferncesDB_->HandleDataBaseMap(datas, bundleOption);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: HandleDataBaseMap_0400
 * @tc.desc: test HandleDataBaseMap.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationPreferencesDatabaseTwoTest, HandleDataBaseMap_0400, TestSize.Level1)
{
    MockIsOsAccountExists(false);
    NotificationBundleOption bundle1 = NotificationBundleOption("ohos.example.demo", 10000);
    NotificationBundleOption bundle2 = NotificationBundleOption("ohos.example.demo", 10001);
    std::unordered_map<std::string, std::string> datas;
    std::vector<NotificationBundleOption> bundleOption;
    bundleOption.push_back(bundle1);
    bundleOption.push_back(bundle2);
    int32_t userId = -1;
    auto ret = preferncesDB_->HandleDataBaseMap(datas, bundleOption, userId);
    ASSERT_EQ(ret, false);
    MockIsOsAccountExists(true);
}

/**
 * @tc.name      : GetAllNotificationEnabledBundles_00100
 * @tc.number    : GetAllNotificationEnabledBundles
 * @tc.desc      : Check func GetAllNotificationEnabledBundles, return false
 */
HWTEST_F(NotificationPreferencesDatabaseTwoTest, GetAllNotificationEnabledBundles_00100, Function | SmallTest | Level1)
{
    MockIsOsAccountExists(false);
    std::vector<NotificationBundleOption> bundleOption;
    int32_t userId = -1;
    ASSERT_EQ(false, preferncesDB_->GetAllNotificationEnabledBundles(bundleOption, userId));
    MockIsOsAccountExists(true);
}
}  // namespace Notification
}  // namespace OHOS
