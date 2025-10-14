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

#include "gtest/gtest.h"

#define private public

#include "notification_liveview_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class NotificationLiveViewUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: CheckData_100
 * @tc.desc: Test live view check data.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationLiveViewUtilTest, CheckData_100, Function | SmallTest | Level1)
{
    std::vector<std::string> data;
    data.emplace_back("bundle_1");
    auto check = std::make_shared<LiveViewCheckParam>(data);
    std::string id = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(check);
    ASSERT_EQ(id.empty(), false);

    std::shared_ptr<LiveViewCheckParam> checkData;
    bool exist = NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData("id", checkData);
    ASSERT_EQ(exist, false);

    exist = NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(id, checkData);
    ASSERT_EQ(exist, true);

    NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(id);
}

/**
 * @tc.name: CheckData_200
 * @tc.desc: Test live view check data.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationLiveViewUtilTest, CheckData_200, Function | SmallTest | Level1)
{
    NotificationLiveViewUtils::GetInstance().RemoveLiveViewRebuild(100);
    bool check = NotificationLiveViewUtils::GetInstance().CheckLiveViewRebuild(100);
    ASSERT_EQ(check, true);
    // invoke again
    check = NotificationLiveViewUtils::GetInstance().CheckLiveViewRebuild(100);
    ASSERT_EQ(check, false);
    NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(100,
        NotificationLiveViewUtils::ERASE_FLAG_INIT);
    check = NotificationLiveViewUtils::GetInstance().CheckLiveViewRebuild(100);
    ASSERT_EQ(check, true);
}
}
}
