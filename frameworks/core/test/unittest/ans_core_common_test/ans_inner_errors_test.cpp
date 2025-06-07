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

#include "ans_inner_errors.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

class AnsInnerErrorsTest : public ::testing::Test {
protected:
void SetUp() override {}
void TearDown() override {}
};

HWTEST_F(AnsInnerErrorsTest, GetAnsErrMessage_001, TestSize.Level1)
{
    // Arrange
    uint32_t errCode = ERROR_NOTIFICATION_NOT_EXIST;
    std::string defaultMsg = "Default error message";
    std::string expectedMsg = "The notification does not exist";

    // Act
    std::string actualMsg = GetAnsErrMessage(errCode, defaultMsg);

    // Assert
    EXPECT_EQ(expectedMsg, actualMsg);
}

HWTEST_F(AnsInnerErrorsTest, GetAnsErrMessage_002, TestSize.Level1)
{
    // Arrange
    uint32_t errCode = 999999; // Assuming 999999 is an invalid error code in ANS_ERROR_CODE_MESSAGE_MAP
    std::string defaultMsg = "Default error message";
    std::string expectedMsg = defaultMsg;

    // Act
    std::string actualMsg = GetAnsErrMessage(errCode, defaultMsg);

    // Assert
    EXPECT_EQ(expectedMsg, actualMsg);
}

HWTEST_F(AnsInnerErrorsTest, ErrorToExternal_ShouldReturnCorrectExternalCode_WhenInternalCodeIsKnown, TestSize.Level1)
{
    // Arrange
    uint32_t internalCode = ERR_ANS_DISTRIBUTED_GET_INFO_FAILED;
    int32_t expectedExternalCode = ERROR_DISTRIBUTED_OPERATION_FAILED;

    // Act
    int32_t actualExternalCode = ErrorToExternal(internalCode);

    // Assert
    EXPECT_EQ(expectedExternalCode, actualExternalCode);
}
HWTEST_F(AnsInnerErrorsTest, ErrorToExternal_ShouldReturnDefaultCode_WhenInternalCodeIsUnknown, TestSize.Level1)
{
    // Arrange
    uint32_t internalCode = 9999;
    int32_t expectedExternalCode = ERROR_INTERNAL_ERROR;

    // Act
    int32_t actualExternalCode = ErrorToExternal(internalCode);

    // Assert
    EXPECT_EQ(expectedExternalCode, actualExternalCode);
}