/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "file_utils.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationFileUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name : NotificationFileUtils_001
 * @tc.number :
 * @tc.desc : Test constructure.
 */
HWTEST_F(NotificationFileUtilsTest, NotificationFileUtils_001, Function | SmallTest | Level1)
{
    const char* filePath = nullptr;
    std::vector<nlohmann::json> NotificationConfigJson;
    auto ret = FileUtils::GetJsonByFilePath(filePath, NotificationConfigJson);
    EXPECT_EQ(ret, false);

    const char* filePath1 = "etc/notification/temp.json";;
    ret = FileUtils::GetJsonByFilePath(filePath1, NotificationConfigJson);
    EXPECT_EQ(ret, false);
}
} // namespace Notification
} // namespace OHOS