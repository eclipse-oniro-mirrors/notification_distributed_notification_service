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

#define private public
#define protected public
#include "notification_classification.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationClassificationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetClassification_00001
 * @tc.desc: Test SetClassification and GetClassification with normal string.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetClassification_00001, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    classification.SetClassification("social");
    EXPECT_EQ(classification.GetClassification(), "social");
}

/**
 * @tc.name: SetClassification_00002
 * @tc.desc: Test SetClassification and GetClassification with empty string.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetClassification_00002, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    classification.SetClassification("");
    EXPECT_EQ(classification.GetClassification(), "");
}

/**
 * @tc.name: SetSubClassification_00001
 * @tc.desc: Test SetSubClassification and GetSubClassification with normal string.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetSubClassification_00001, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    classification.SetSubClassification("chat");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
}

/**
 * @tc.name: SetSubClassification_00002
 * @tc.desc: Test SetSubClassification and GetSubClassification with empty string.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetSubClassification_00002, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    classification.SetSubClassification("");
    EXPECT_EQ(classification.GetSubClassification(), "");
}

/**
 * @tc.name: Dump_00001
 * @tc.desc: Test Dump with classification and subClassification set.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Dump_00001, Function | SmallTest | Level1)
{
    NotificationClassification classification("social", "chat");
    std::string dumpResult = classification.Dump();
    std::string expected = "NotificationClassification{ classification = social, subClassification = chat }";
    EXPECT_EQ(dumpResult, expected);
}

/**
 * @tc.name: Dump_00002
 * @tc.desc: Test Dump with default empty classification and subClassification.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Dump_00002, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    std::string dumpResult = classification.Dump();
    std::string expected = "NotificationClassification{ classification = , subClassification =  }";
    EXPECT_EQ(dumpResult, expected);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling with valid parcel.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Marshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    EXPECT_EQ(classification.Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling with valid parcel data (roundtrip test).
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    EXPECT_EQ(classification.Marshalling(parcel), true);

    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "social");
    EXPECT_EQ(result->GetSubClassification(), "chat");
    delete result;
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling with empty strings (roundtrip test).
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("", "");
    EXPECT_EQ(classification.Marshalling(parcel), true);

    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "");
    EXPECT_EQ(result->GetSubClassification(), "");
    delete result;
}

/**
 * @tc.name: ReadFromParcel_00001
 * @tc.desc: Test ReadFromParcel with valid parcel data.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00001, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteString("social");
    parcel.WriteString("chat");

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
}

/**
 * @tc.name: ReadFromParcel_00002
 * @tc.desc: Test ReadFromParcel with empty strings.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    parcel.WriteString("");
    parcel.WriteString("");

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "");
    EXPECT_EQ(classification.GetSubClassification(), "");
}

/**
 * @tc.name: Constructor_00001
 * @tc.desc: Test parameterized constructor with classification and subClassification.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Constructor_00001, Function | SmallTest | Level1)
{
    NotificationClassification classification("social", "chat");
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
}

/**
 * @tc.name: Constructor_00002
 * @tc.desc: Test default constructor with empty classification and subClassification.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Constructor_00002, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    EXPECT_EQ(classification.GetClassification(), "");
    EXPECT_EQ(classification.GetSubClassification(), "");
}
}  // namespace Notification
}  // namespace OHOS