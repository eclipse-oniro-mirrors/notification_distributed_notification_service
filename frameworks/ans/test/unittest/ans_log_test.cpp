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

#include "ans_log_wrapper.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class AnsLogTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AnsLogTest::SetUpTestCase()
{}

void AnsLogTest::TearDownTestCase()
{}

void AnsLogTest::SetUp()
{}

void AnsLogTest::TearDown()
{}

/*
 * @tc.name: AnsLogTest_001
 * @tc.desc: test GetBriefFileName function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsLogTest_001, TestSize.Level1)
{
    std::string fileName = "../function/EventFwk/test.cpp";
    std::string exceptStr = "test.cpp";

    std::string result = AnsLogWrapper::GetBriefFileName(fileName.c_str());
    EXPECT_EQ(exceptStr, result);
}

/*
 * @tc.name: AnsLogTest_002
 * @tc.desc: test GetBriefFileName function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsLogTest_002, TestSize.Level1)
{
    std::string fileName = "test.cpp";
    std::string exceptStr = "";

    std::string result = AnsLogWrapper::GetBriefFileName(fileName.c_str());
    EXPECT_EQ(exceptStr, result);

    fileName = "";
    result = AnsLogWrapper::GetBriefFileName(fileName.c_str());
    EXPECT_EQ(exceptStr, result);

    result = AnsLogWrapper::GetBriefFileName(nullptr);
    EXPECT_EQ(exceptStr, result);
}
}
}