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
 * @tc.name: GetInstance_00001
 * @tc.desc: Test GetInstance returns the same instance.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, GetInstance_00001, Function | SmallTest | Level1)
{
    auto& instance1 = NotificationLiveViewUtils::GetInstance();
    auto& instance2 = NotificationLiveViewUtils::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: AddLiveViewCheckData_00001
 * @tc.desc: Test AddLiveViewCheckData with valid param.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, AddLiveViewCheckData_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles;
    bundles.emplace_back("bundle1");
    bundles.emplace_back("bundle2");
    auto param = std::make_shared<LiveViewCheckParam>(bundles);
    std::string requestId = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(param);
    EXPECT_FALSE(requestId.empty());
    NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
}

/**
 * @tc.name: GetLiveViewCheckData_00001
 * @tc.desc: Test GetLiveViewCheckData with non-existent requestId.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, GetLiveViewCheckData_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<LiveViewCheckParam> data;
    bool result = NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData("invalid_id", data);
    EXPECT_FALSE(result);
    EXPECT_EQ(data, nullptr);
}

/**
 * @tc.name: GetLiveViewCheckData_00002
 * @tc.desc: Test GetLiveViewCheckData with valid requestId.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, GetLiveViewCheckData_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles;
    bundles.emplace_back("test_bundle");
    auto param = std::make_shared<LiveViewCheckParam>(bundles);
    param->retryTime = 5;
    
    std::string requestId = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(param);
    std::shared_ptr<LiveViewCheckParam> retrievedData;
    bool result = NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(requestId, retrievedData);
    
    EXPECT_TRUE(result);
    EXPECT_NE(retrievedData, nullptr);
    EXPECT_EQ(retrievedData->retryTime, 5);
    EXPECT_EQ(retrievedData->bundlesName.size(), 1);
    
    NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
}

/**
 * @tc.name: EraseLiveViewCheckData_00001
 * @tc.desc: Test EraseLiveViewCheckData removes data successfully.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, EraseLiveViewCheckData_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles;
    bundles.emplace_back("bundle");
    auto param = std::make_shared<LiveViewCheckParam>(bundles);
    
    std::string requestId = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(param);
    
    std::shared_ptr<LiveViewCheckParam> data;
    EXPECT_TRUE(NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(requestId, data));
    
    NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(requestId);
    
    data = nullptr;
    EXPECT_FALSE(NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(requestId, data));
}

/**
 * @tc.name: SetLiveViewRebuild_00001
 * @tc.desc: Test SetLiveViewRebuild with invalid data value.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, SetLiveViewRebuild_00001, Function | SmallTest | Level1)
{
    int32_t userId = 400;
    NotificationLiveViewUtils::GetInstance().RemoveLiveViewRebuild(userId);
    
    NotificationLiveViewUtils::GetInstance().SetLiveViewRebuild(userId, 99);
    
    auto& utils = NotificationLiveViewUtils::GetInstance();
    std::lock_guard<ffrt::mutex> lock(utils.eraseMutex);
    EXPECT_EQ(utils.eraseFlag.find(userId), utils.eraseFlag.end());
}

/**
 * @tc.name: CheckLiveViewRebuild_00001
 * @tc.desc: Test CheckLiveViewRebuild with new userId.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, CheckLiveViewRebuild_00001, Function | SmallTest | Level1)
{
    int32_t userId = 600;
    NotificationLiveViewUtils::GetInstance().RemoveLiveViewRebuild(userId);
    
    auto& utils = NotificationLiveViewUtils::GetInstance();
    utils.eraseFlag.erase(userId);
    
    bool result = NotificationLiveViewUtils::GetInstance().CheckLiveViewRebuild(userId);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: LiveViewCheckParam_00001
 * @tc.desc: Test LiveViewCheckParam default constructor.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, LiveViewCheckParam_00001, Function | SmallTest | Level1)
{
    LiveViewCheckParam param;
    EXPECT_EQ(param.retryTime, 0);
    EXPECT_EQ(param.bundlesName.size(), 0);
}

/**
 * @tc.name: LiveViewCheckParam_00002
 * @tc.desc: Test LiveViewCheckParam constructor with bundles.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, LiveViewCheckParam_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles;
    bundles.emplace_back("bundle1");
    bundles.emplace_back("bundle2");
    bundles.emplace_back("bundle3");
    
    LiveViewCheckParam param(bundles);
    EXPECT_EQ(param.retryTime, 0);
    EXPECT_EQ(param.bundlesName.size(), 3);
    EXPECT_EQ(param.bundlesName[0], "bundle1");
    EXPECT_EQ(param.bundlesName[1], "bundle2");
    EXPECT_EQ(param.bundlesName[2], "bundle3");
}

/**
 * @tc.name: CheckData_MultipleOperations_00001
 * @tc.desc: Test multiple add/get/erase operations.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationLiveViewUtilTest, CheckData_MultipleOperations_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> bundles1;
    bundles1.emplace_back("bundle1");
    auto param1 = std::make_shared<LiveViewCheckParam>(bundles1);
    std::string id1 = NotificationLiveViewUtils::GetInstance().AddLiveViewCheckData(param1);
    EXPECT_FALSE(id1.empty());

    std::shared_ptr<LiveViewCheckParam> data1;
    EXPECT_TRUE(NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(id1, data1));
    EXPECT_EQ(data1->bundlesName[0], "bundle1");
    NotificationLiveViewUtils::GetInstance().EraseLiveViewCheckData(id1);
    EXPECT_FALSE(NotificationLiveViewUtils::GetInstance().GetLiveViewCheckData(id1, data1));
}
}
}
