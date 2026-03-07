/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "notification_parameters.h"
#include "want.h"
#include "want_params.h"
#include "parcel.h"

using namespace testing::ext;
namespace OHOS::Notification {

class NotificationParametersTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NotificationParametersTest::SetUpTestCase()
{
}

void NotificationParametersTest::TearDownTestCase()
{
}

void NotificationParametersTest::SetUp()
{
}

void NotificationParametersTest::TearDown()
{
}

/**
 * @tc.number    : NotificationParameters_Marshalling_00001
 * @tc.name      : Test Marshalling and Unmarshalling with data
 * @tc.desc      : Test serialization and deserialization with valid data
 * @tc.type      : FUNC
 */
HWTEST_F(NotificationParametersTest, Marshalling_00001, Function | SmallTest | Level1)
{
    // Step 1: Create NotificationParameters object with data
    sptr<NotificationParameters> parameters = new (std::nothrow) NotificationParameters();
    ASSERT_NE(parameters, nullptr);

    std::string action = "test.action";
    std::string uri = "test://uri";
    auto wantParams = std::make_shared<AAFwk::WantParams>();

    parameters->SetWantAction(action);
    parameters->SetWantUri(uri);
    parameters->SetWantParameters(wantParams);

    // Step 2: Serialize to Parcel
    Parcel parcel;
    bool result = parameters->Marshalling(parcel);
    ASSERT_EQ(result, true);

    // Step 3: Deserialize from Parcel
    auto unmarshalled = NotificationParameters::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);

    // Step 4: Verify data integrity
    EXPECT_EQ(unmarshalled->GetWantAction(), action);
    EXPECT_EQ(unmarshalled->GetWantUri(), uri);
    EXPECT_NE(unmarshalled->GetWantParameters(), nullptr);

    delete unmarshalled;
}

/**
 * @tc.number    : NotificationParameters_SetWantAction_00001
 * @tc.name      : Test SetWantAction and GetWantAction
 * @tc.desc      : Test setting and getting want action
 * @tc.type      : FUNC
 */
HWTEST_F(NotificationParametersTest, SetWantAction_00001, Function | SmallTest | Level1)
{
    // Step 1: Create NotificationParameters object
    NotificationParameters parameters;
    std::string action = "test.action";

    // Step 2: Set and verify want action
    parameters.SetWantAction(action);
    EXPECT_EQ(parameters.GetWantAction(), action);
}

/**
 * @tc.number    : NotificationParameters_SetWantUri_00001
 * @tc.name      : Test SetWantUri and GetWantUri
 * @tc.desc      : Test setting and getting want URI
 * @tc.type      : FUNC
 */
HWTEST_F(NotificationParametersTest, SetWantUri_00001, Function | SmallTest | Level1)
{
    // Step 1: Create NotificationParameters object
    NotificationParameters parameters;
    std::string uri = "test://uri";

    // Step 2: Set and verify want URI
    parameters.SetWantUri(uri);
    EXPECT_EQ(parameters.GetWantUri(), uri);
}

/**
 * @tc.number    : NotificationParameters_SetWantParameters_00001
 * @tc.name      : Test SetWantParameters and GetWantParameters
 * @tc.desc      : Test setting and getting want parameters
 * @tc.type      : FUNC
 * @tc.level     : Level1
 */
HWTEST_F(NotificationParametersTest, SetWantParameters_00001, Function | SmallTest | Level1)
{
    // Step 1: Create NotificationParameters object
    NotificationParameters parameters;
    auto wantParams = std::make_shared<AAFwk::WantParams>();

    // Step 2: Set and verify want parameters
    parameters.SetWantParameters(wantParams);
    EXPECT_NE(parameters.GetWantParameters(), nullptr);
}

/**
 * @tc.number    : NotificationParameters_Marshalling_00002
 * @tc.name      : Test Marshalling and Unmarshalling without data
 * @tc.desc      : Test serialization and deserialization with empty data
 * @tc.type      : FUNC
 * @tc.level     : Level1
 */
HWTEST_F(NotificationParametersTest, Marshalling_00002, Function | SmallTest | Level1)
{
    // Step 1: Create empty NotificationParameters object
    sptr<NotificationParameters>  parameters = new (std::nothrow) NotificationParameters();
    ASSERT_NE(parameters, nullptr);

    // Step 2: Serialize to Parcel
    Parcel parcel;
    bool result = parameters->Marshalling(parcel);
    ASSERT_EQ(result, true);

    // Step 3: Deserialize from Parcel
    auto unmarshalled = NotificationParameters::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);

    // Step 4: Verify empty data
    EXPECT_EQ(unmarshalled->GetWantAction(), "");
    EXPECT_EQ(unmarshalled->GetWantUri(), "");
    EXPECT_EQ(unmarshalled->GetWantParameters(), nullptr);

    delete unmarshalled;
}
}