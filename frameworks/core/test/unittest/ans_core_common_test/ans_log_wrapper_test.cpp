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

#include "gtest/gtest.h"

#include "ans_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsLogWrapperTest : public ::testing::Test {
protected:
void SetUp() override {}
void TearDown() override {}
};

HWTEST_F(AnsLogWrapperTest, StringAnonymous_ShouldReturnEmpty_WhenDataIsEmpty, TestSize.Level1)
{
    std::string data = "";
    std::string result = StringAnonymous(data);
    EXPECT_EQ(result, "");
}

/**
* @tc.name  : StringAnonymous_ShouldReturnFirstCharAndAnonymous_WhenDataLengthIs3
* @tc.number: 002
* @tc.desc  : 当输入数据长度为3时，函数应返回第一个字符加匿名字符串
*/
HWTEST_F(AnsLogWrapperTest, StringAnonymous_ShouldReturnFirstCharAndAnonymous_WhenDataLengthIs3, TestSize.Level1)
{
    std::string data = "abc";
    std::string result = StringAnonymous(data);
    EXPECT_EQ(result, "a******");
}

/**
* @tc.name  : StringAnonymous_ShouldReturnFirstCharAndAnonymous_WhenDataLengthIs4
* @tc.number: 003
* @tc.desc  : 当输入数据长度为4时，函数应返回第一个字符加匿名字符串
*/
HWTEST_F(AnsLogWrapperTest, StringAnonymous_ShouldReturnFirstCharAndAnonymous_WhenDataLengthIs4, TestSize.Level1)
{
    std::string data = "abcd";
    std::string result = StringAnonymous(data);
    EXPECT_EQ(result, "a******");
}

/**
* @tc.name  : StringAnonymous_ShouldReturnFirstTwoCharsAnonymousAndLastTwoChars_WhenDataLengthIs6
* @tc.number: 005
* @tc.desc  : 当输入数据长度为6时，函数应返回前两个字符加匿名字符串再加后两个字符
*/
HWTEST_F(AnsLogWrapperTest, StringAnonymous_ShouldReturnFirstTwoCharsAnonymousAndLastTwoChars_WhenDataLengthIs6,
    TestSize.Level1)
{
    std::string data = "abcdef";
    std::string result = StringAnonymous(data);
    EXPECT_EQ(result, "ab******ef");
}

/**
* @tc.name  : StringAnonymous_ShouldReturnFirstTwoCharsAnonymousAndLastTwoChars_WhenDataLengthIs7
* @tc.number: 006
* @tc.desc  : 当输入数据长度为7时，函数应返回前两个字符加匿名字符串再加后两个字符
*/
HWTEST_F(AnsLogWrapperTest, StringAnonymous_ShouldReturnFirstTwoCharsAnonymousAndLastTwoChars_WhenDataLengthIs7,
    TestSize.Level1)
{
    std::string data = "abcdefg";
    std::string result = StringAnonymous(data);
    EXPECT_EQ(result, "ab******fg");
}