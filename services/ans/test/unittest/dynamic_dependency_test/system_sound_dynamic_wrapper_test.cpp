/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License License at
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
#include <vector>
#include <string>
#include <mutex>

#include "system_sound_dynamic_wrapper.h"
#include "mock_system_sound_manager.h"

#define private public

using namespace testing;
using namespace OHOS::Notification;
using namespace OHOS::Media;

namespace OHOS {
namespace Notification {

class SystemSoundDynamicWrapperTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static std::shared_ptr<MockSystemSoundManager> mockSystemSoundManager_;
};

std::shared_ptr<MockSystemSoundManager> SystemSoundDynamicWrapperTest::mockSystemSoundManager_ = nullptr;

void SystemSoundDynamicSystemWrapperTest::SetUpTestCase()
{
    mockSystemSoundManager_ = std::make_shared<MockSystemSoundManager>();
}

void SystemSoundDynamicWrapperTest::TearDownTestCase()
{
    mockSystemSoundManager_.reset();
}

void SystemSoundDynamicWrapperTest::SetUp()
{
}

void SystemSoundDynamicWrapperTest::TearDown()
{
}

HWTEST_F(SystemSoundDynamicWrapperTest, GetInstance_00001, Function | SmallTest | Level1)
{
    auto& instance1 = SystemSoundDynamicWrapper::GetInstance();
    auto& instance2 = SystemSoundDynamicWrapper::GetInstance();
    
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedTone_00001, Function | SmallTest | Level1)
{
    std::string uri = "test_uri_1";
    
    EXPECT_CALL(*mockSystemSoundManager_, RemoveCustomizedTone(testing::_, uri))
        .WillOnce(testing::Return(1));
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedTone(uri);
    EXPECT_TRUE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedTone_00002, Function | SmallTest | Level1)
{
    std::string uri = "";
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedTone(uri);
    EXPECT_TRUE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedTone_00003, Function | SmallTest | Level1)
{
    std::string uri = "test_uri_2";
    
    EXPECT_CALL(*mockSystemSoundManager_, RemoveCustomizedTone(testing::_, uri))
        .WillOnce(testing::Return(0));
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedTone(uri);
    EXPECT_FALSE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedToneList_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> uris = {"uri1", "uri2", "uri3"};
    SystemSoundError errCode = SystemSoundError::ERROR_OK;
    std::vector<std::pair<std::string, SystemSoundError>> mockResults = {
        {"uri1", SystemSoundError::ERROR_OK},
        {"uri2", SystemSoundError::ERROR_OK},
        {"uri3", SystemSoundError::ERROR_OK}
    };
    
    EXPECT_CALL(*mockSystemSoundManager_, RemoveCustomizedToneList(uris, testing::Ref(errCode)))
        .WillOnce(testing::Return(mockResults));
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedToneList(uris);
    EXPECT_TRUE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedToneList_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> uris;
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedToneList(uris);
    EXPECT_TRUE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedToneList_00003, Function | SmallTest | Level1)
{
    std::vector<std::string> uris = {"uri1", "uri2"};
    SystemSoundError errCode = SystemSoundError::ERROR_OK;
    std::vector<std::pair<std::string, SystemSoundError>> mockResults = {
        {"uri1", SystemSoundError::ERROR_INVALID_PARAM},
        {"uri2", SystemSoundError::ERROR_OK}
    };
    
    EXPECT_CALL(*mockSystemSoundManager_, RemoveCustomizedToneList(uris, testing::Ref(errCode)))
        .WillOnce(testing::Return(mockResults))
        .WillOnce(testing::Return(mockResults));
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedToneList(uris);
    EXPECT_TRUE(result);
}

HWTEST_F(SystemSoundDynamicWrapperTest, RemoveCustomizedToneList_00004, Function | SmallTest | Level1)
{
    std::vector<std::string> uris = {"uri1"};
    SystemSoundError errCode = SystemSoundError::ERROR_OK;
    std::vector<std::pair<std::string, SystemSoundError>> mockResults = {
        {"uri1", SystemSoundError::ERROR_IO}
    };
    
    EXPECT_CALL(*mockSystemSoundManager_, RemoveCustomizedToneList(uris, testing::Ref(errCode)))
        .WillOnce(testing::Return(mockResults))
        .WillOnce(testing::Return(mockResults));
    
    bool result = SystemSoundDynamicWrapper::GetInstance().RemoveCustomizedToneList(uris);
    EXPECT_TRUE(result);
}

}
