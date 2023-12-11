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

#include "notification_config_parse.h"
#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class NotificationConfigFileTest : public testing::Test {
public:
    NotificationConfigFileTest()
    {}
    ~NotificationConfigFileTest()
    {}

    static void SetUpTestCas(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NotificationConfigFileTest::SetUpTestCas(void)
{}

void NotificationConfigFileTest::TearDownTestCase(void)
{}

void NotificationConfigFileTest::SetUp(void)
{}

void NotificationConfigFileTest::TearDown(void)
{}

/**
 * @tc.name: parseNotificationConfigCcmFileTest_001
 * @tc.desc: parseNotificationConfigCcmFile Test
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationConfigFileTest, parseNotificationConfigCcmFileTest_001, TestSize.Level1)
{
    std::string filepath = nullptr;
    std::map<std::string, uint32_t> slotFlagsMap;
    EXPECT_EQ(NotificationConfigFile::parseNotificationConfigCcmFile(filepath, slotFlagsMap), false);
}

/**
 * @tc.name: getNotificationSlotFlagConfigTest_001
 * @tc.desc: getNotificationSlotFlagConfig Test
 * @tc.type: FUNC
 * @tc.require: issueNumber
 */
HWTEST_F(NotificationConfigFileTest, getNotificationSlotFlagConfigTest_001, TestSize.Level1)
{
    std::string filepath = nullptr;
    std::map<std::string, uint32_t> slotFlagsMap;
    EXPECT_EQ(NotificationConfigFile::getNotificationSlotFlagConfig(filepath, slotFlagsMap), true);
}
}   //namespace Notification
}   //namespace OHOS