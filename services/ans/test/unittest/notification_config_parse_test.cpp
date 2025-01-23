/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "notification_config_parse.h"
#undef private

#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace Notification {

namespace {
const std::string TEST_BUNDLENAME = "bundleName";
const std::string TEST_UID = "uid";
const std::string TEST_OWNER_BUNDLENAME = "com.example.test";
const int32_t TEST_CREATOR_UID = 12345;
} // namespace

class NotificationConfigParseTest : public testing::Test {
public:
    static void SetUpTestCas() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name      : GetCollaborationFilter_00100
 * @tc.number    : GetCollaborationFilter_00100
 * @tc.desc      : Test GetCollaborationFilter function without json.
 */
HWTEST_F(NotificationConfigParseTest, GetCollaborationFilter_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationConfigParse> configParse = std::make_shared<NotificationConfigParse>();
    if (!configParse->notificationConfigJsons_.empty()) {
        configParse->notificationConfigJsons_.clear();
    }
    configParse->GetCollaborationFilter();

    EXPECT_TRUE(configParse->uidList_.empty());
    EXPECT_TRUE(configParse->bundleNameList_.empty());

    bool result = configParse->IsInCollaborationFilter(TEST_OWNER_BUNDLENAME, TEST_CREATOR_UID);
    EXPECT_FALSE(result);
}

/**
 * @tc.name      : GetCollaborationFilter_00200
 * @tc.number    : GetCollaborationFilter_00200
 * @tc.desc      : Test GetCollaborationFilter function.
 */
HWTEST_F(NotificationConfigParseTest, GetCollaborationFilter_00200, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationConfigParse> configParse = std::make_shared<NotificationConfigParse>();
    nlohmann::json jsonObject = {
        {"notificationService", {
            {"collaborationFilter", {
                {"uid", {12345, 67890}},
                {"bundleName", {"com.example.test"}}
            }}
        }}
    };
    if (!configParse->notificationConfigJsons_.empty()) {
        configParse->notificationConfigJsons_.clear();
    }
    configParse->notificationConfigJsons_.push_back(jsonObject);
    configParse->GetCollaborationFilter();

    EXPECT_FALSE(configParse->uidList_.empty());
    EXPECT_FALSE(configParse->bundleNameList_.empty());

    bool result = configParse->IsInCollaborationFilter("", 0);
    EXPECT_FALSE(result);

    result = configParse->IsInCollaborationFilter("", TEST_CREATOR_UID);
    EXPECT_TRUE(result);

    result = configParse->IsInCollaborationFilter(TEST_OWNER_BUNDLENAME, 0);
    EXPECT_TRUE(result);
}

/**
 * @tc.name      : GetFilterUidAndBundleName_00100
 * @tc.number    : GetFilterUidAndBundleName_00100
 * @tc.desc      : Test GetFilterUidAndBundleName function with empty bundleName, uid.
 */
HWTEST_F(NotificationConfigParseTest, GetFilterUidAndBundleName_00100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationConfigParse> configParse = std::make_shared<NotificationConfigParse>();
    nlohmann::json emptyCollaborationFilter = {
        {"notificationService", {
            {"collaborationFilter", {
                {"uid", nlohmann::json::array()},
                {"bundleName", nlohmann::json::array()}
            }}
        }}
    };
    if (!configParse->notificationConfigJsons_.empty()) {
        configParse->notificationConfigJsons_.clear();
    }
    configParse->notificationConfigJsons_.push_back(emptyCollaborationFilter);
    bool ret = configParse->GetFilterUidAndBundleName(TEST_BUNDLENAME);
    EXPECT_TRUE(ret);
}
}   //namespace Notification
}   //namespace OHOS
