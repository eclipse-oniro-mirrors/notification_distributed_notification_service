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
    std::string expected = "NotificationClassification{ classification = social, subClassification = chat, "
        "priorityNotificationType = OTHER, expiredTime = 0, source = -1, "
        "classificationSet = true, priorityInfoSet = false }";
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
    std::string expected = "NotificationClassification{ classification = , subClassification = , "
        "priorityNotificationType = OTHER, expiredTime = 0, source = -1, "
        "classificationSet = false, priorityInfoSet = false }";
    EXPECT_EQ(dumpResult, expected);
}

/**
 * @tc.name: Dump_00003
 * @tc.desc: Test Dump with non-default priority info values.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Dump_00003, Function | SmallTest | Level1)
{
    NotificationClassification classification("social", "chat");
    classification.priorityInfo_.priorityNotificationType_ =
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
    classification.priorityInfo_.expiredTime_ = 1735689600000;
    classification.priorityInfo_.source_ = static_cast<int32_t>(
        NotificationConstant::PrioritySourceResult::AI);
    std::string dumpResult = classification.Dump();
    std::string expected = "NotificationClassification{ classification = social, subClassification = chat, "
        "priorityNotificationType = " + std::string(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE) +
        ", expiredTime = 1735689600000, source = " +
        std::to_string(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)) +
        ", classificationSet = true, priorityInfoSet = false }";
    EXPECT_EQ(dumpResult, expected);
}

/**
 * @tc.name: IsClassificationSet_00001
 * @tc.desc: Test the classification dimension flag: default constructed stays unset,
 *           the two string constructor marks it set and the string setters mark it set.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, IsClassificationSet_00001, Function | SmallTest | Level1)
{
    NotificationClassification unset;
    EXPECT_EQ(unset.IsClassificationSet(), false);

    NotificationClassification constructed("social", "chat");
    EXPECT_EQ(constructed.IsClassificationSet(), true);

    NotificationClassification setterOnly;
    setterOnly.SetClassification("social");
    EXPECT_EQ(setterOnly.IsClassificationSet(), true);

    NotificationClassification subOnly;
    subOnly.SetSubClassification("chat");
    EXPECT_EQ(subOnly.IsClassificationSet(), true);
}

/**
 * @tc.name: ReadFromParcel_00009
 * @tc.desc: Test the dimension flag tail tolerance: a parcel written before the flags
 *           existed (the strings plus the priority triple only) fails the flag read and
 *           both flags keep the default unset, so the round merges as "no dimension
 *           set" and the cached values are kept, without failing the whole
 *           unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00009, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE), true);
    EXPECT_EQ(parcel.WriteInt64(1735689600000), true);
    EXPECT_EQ(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.IsClassificationSet(), false);
    EXPECT_EQ(classification.IsPriorityInfoSet(), false);
}

/**
 * @tc.name: Unmarshalling_00006
 * @tc.desc: Test the dimension flag round trip: the two flags sit at the parcel tail
 *           after the priority triple and survive the marshal / unmarshal round trip in
 *           both dimension combinations (aggregation only and priority only).
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00006, Function | SmallTest | Level1)
{
    NotificationClassification aggregationOnly("social", "chat");
    Parcel aggregationParcel;
    EXPECT_EQ(aggregationOnly.Marshalling(aggregationParcel), true);
    NotificationClassification *aggregationResult =
        NotificationClassification::Unmarshalling(aggregationParcel);
    ASSERT_NE(aggregationResult, nullptr);
    EXPECT_EQ(aggregationResult->IsClassificationSet(), true);
    EXPECT_EQ(aggregationResult->IsPriorityInfoSet(), false);
    EXPECT_EQ(aggregationResult->GetClassification(), "social");
    delete aggregationResult;

    NotificationClassification unset;
    Parcel unsetParcel;
    EXPECT_EQ(unset.Marshalling(unsetParcel), true);
    NotificationClassification *unsetResult = NotificationClassification::Unmarshalling(unsetParcel);
    ASSERT_NE(unsetResult, nullptr);
    EXPECT_EQ(unsetResult->IsClassificationSet(), false);
    EXPECT_EQ(unsetResult->IsPriorityInfoSet(), false);
    delete unsetResult;
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
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling appends the priority info triple at the parcel tail in type, expiredTime,
 *           source order after subClassification.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Marshalling_00002, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    classification.priorityInfo_.priorityNotificationType_ =
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
    classification.priorityInfo_.expiredTime_ = 1735689600000;
    classification.priorityInfo_.source_ = static_cast<int32_t>(
        NotificationConstant::PrioritySourceResult::AI);
    EXPECT_EQ(classification.Marshalling(parcel), true);

    std::string classificationValue;
    std::string subClassificationValue;
    std::string priorityNotificationType;
    int64_t expiredTime = 0;
    int32_t source = 0;
    EXPECT_EQ(parcel.ReadString(classificationValue), true);
    EXPECT_EQ(parcel.ReadString(subClassificationValue), true);
    EXPECT_EQ(parcel.ReadString(priorityNotificationType), true);
    EXPECT_EQ(parcel.ReadInt64(expiredTime), true);
    EXPECT_EQ(parcel.ReadInt32(source), true);

    EXPECT_EQ(classificationValue, "social");
    EXPECT_EQ(subClassificationValue, "chat");
    EXPECT_EQ(priorityNotificationType, NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(expiredTime, 1735689600000);
    EXPECT_EQ(source, static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
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
 * @tc.name: Unmarshalling_00003
 * @tc.desc: Test Unmarshalling roundtrip with all five fields including non-default priority info.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    classification.priorityInfo_.priorityNotificationType_ =
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
    classification.priorityInfo_.expiredTime_ = 1735689600000;
    classification.priorityInfo_.source_ = static_cast<int32_t>(
        NotificationConstant::PrioritySourceResult::AI);
    EXPECT_EQ(classification.Marshalling(parcel), true);

    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "social");
    EXPECT_EQ(result->GetSubClassification(), "chat");
    EXPECT_EQ(result->GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(result->GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(result->GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    delete result;
}

/**
 * @tc.name: Unmarshalling_00004
 * @tc.desc: Test Unmarshalling roundtrip keeps the default priority info values.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00004, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    EXPECT_EQ(classification.Marshalling(parcel), true);

    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "social");
    EXPECT_EQ(result->GetSubClassification(), "chat");
    EXPECT_EQ(result->GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::OTHER);
    EXPECT_EQ(result->GetPriorityInfo().GetExpiredTime(), 0);
    EXPECT_EQ(result->GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
    delete result;
}

/**
 * @tc.name: Unmarshalling_00005
 * @tc.desc: Test Unmarshalling with old format parcel keeps default priority info and does not fail.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, Unmarshalling_00005, Function | SmallTest | Level1)
{
    Parcel parcel;
    // Old format parcel written by a previous version: only the two classification strings.
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);

    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetClassification(), "social");
    EXPECT_EQ(result->GetSubClassification(), "chat");
    EXPECT_EQ(result->GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::OTHER);
    EXPECT_EQ(result->GetPriorityInfo().GetExpiredTime(), 0);
    EXPECT_EQ(result->GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
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
 * @tc.name: ReadFromParcel_00003
 * @tc.desc: Test ReadFromParcel reads the priority info triple from the parcel tail in type, expiredTime,
 *           source order after the two classification strings.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00003, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE), true);
    EXPECT_EQ(parcel.WriteInt64(1735689600000), true);
    EXPECT_EQ(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

/**
 * @tc.name: ReadFromParcel_00004
 * @tc.desc: Test ReadFromParcel with old format parcel keeps default priority info and returns true.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00004, Function | SmallTest | Level1)
{
    Parcel parcel;
    // Old format parcel written by a previous version: only the two classification strings.
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::OTHER);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 0);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
}

/**
 * @tc.name: ReadFromParcel_00005
 * @tc.desc: Test old version reader only reading the two classification strings succeeds on new format
 *           data and ignores the trailing priority info fields.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00005, Function | SmallTest | Level1)
{
    Parcel parcel;
    NotificationClassification classification("social", "chat");
    classification.priorityInfo_.priorityNotificationType_ =
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE;
    classification.priorityInfo_.expiredTime_ = 1735689600000;
    classification.priorityInfo_.source_ = static_cast<int32_t>(
        NotificationConstant::PrioritySourceResult::AI);
    EXPECT_EQ(classification.Marshalling(parcel), true);

    // Simulate an old version reader which only reads the two classification strings: the reading
    // succeeds and the trailing priority info fields are simply left unread (ignored).
    std::string classificationValue;
    std::string subClassificationValue;
    EXPECT_EQ(parcel.ReadString(classificationValue), true);
    EXPECT_EQ(parcel.ReadString(subClassificationValue), true);
    EXPECT_EQ(classificationValue, "social");
    EXPECT_EQ(subClassificationValue, "chat");

    // The trailing priority info data keeps intact and unconsumed after the old reader finished.
    std::string priorityNotificationType;
    int64_t expiredTime = 0;
    int32_t source = 0;
    EXPECT_EQ(parcel.ReadString(priorityNotificationType), true);
    EXPECT_EQ(parcel.ReadInt64(expiredTime), true);
    EXPECT_EQ(parcel.ReadInt32(source), true);
    EXPECT_EQ(priorityNotificationType, NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(expiredTime, 1735689600000);
    EXPECT_EQ(source, static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

// The parcel normalization inside ReadFromParcel (expiredTime and source) is unconditional
// (independent of the priority notification feature switch), and the priority type is an
// internal channel value passed through as-is (the type validation is owned by the
// third-party entry NotificationRequest::SetPriorityNotificationType), so the following
// invalid-value cases hold in both switch combinations and are intentionally not wrapped
// in #ifdef.
/**
 * @tc.name: ReadFromParcel_00006
 * @tc.desc: Test ReadFromParcel with a priorityNotificationType not in VALID_PRIORITY_TYPE_LIST
 *           from the parcel keeps the raw value and tolerates the unmarshalling (the type is an
 *           internal channel value passed through as-is).
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00006, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString("HACKER_TYPE"), true);
    EXPECT_EQ(parcel.WriteInt64(1735689600000), true);
    EXPECT_EQ(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(), "HACKER_TYPE");
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

/**
 * @tc.name: ReadFromParcel_00007
 * @tc.desc: Test ReadFromParcel with a priority source out of the valid range from the parcel
 *           replaces it with the default INVALID_RESULT and tolerates the unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00007, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE), true);
    EXPECT_EQ(parcel.WriteInt64(1735689600000), true);
    EXPECT_EQ(parcel.WriteInt32(99), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
}

/**
 * @tc.name: ReadFromParcel_00008
 * @tc.desc: Test ReadFromParcel with a negative expiredTime from the parcel replaces it with the
 *           default 0 (undetermined) and tolerates the unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00008, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE), true);
    EXPECT_EQ(parcel.WriteInt64(-100), true);
    EXPECT_EQ(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 0);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

/**
 * @tc.name: ReadFromParcel_00010
 * @tc.desc: Test ReadFromParcel with an overlong priorityNotificationType (beyond the
 *           internal channel resource bound) keeps the default type and tolerates the
 *           unmarshalling; the other triple members still land through their own
 *           normalization.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, ReadFromParcel_00010, Function | SmallTest | Level1)
{
    Parcel parcel;
    EXPECT_EQ(parcel.WriteString("social"), true);
    EXPECT_EQ(parcel.WriteString("chat"), true);
    EXPECT_EQ(parcel.WriteString(std::string(257, 'A')), true);
    EXPECT_EQ(parcel.WriteInt64(1735689600000), true);
    EXPECT_EQ(parcel.WriteInt32(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI)), true);

    NotificationClassification classification;
    EXPECT_EQ(classification.ReadFromParcel(parcel), true);
    EXPECT_EQ(classification.GetClassification(), "social");
    EXPECT_EQ(classification.GetSubClassification(), "chat");
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::OTHER);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
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

/**
 * @tc.name: GetPriorityInfo_00001
 * @tc.desc: Test GetPriorityInfo returns the default values of the priority info triple.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, GetPriorityInfo_00001, Function | SmallTest | Level1)
{
    NotificationClassification classification;
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::OTHER);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 0);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
}

/**
 * @tc.name: SetSource_00001
 * @tc.desc: Test SetSource with a value below the valid source range keeps INVALID_RESULT.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetSource_00001, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetSource(-10);
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
}

/**
 * @tc.name: SetSource_00002
 * @tc.desc: Test SetSource with values above the valid source range keeps INVALID_RESULT.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetSource_00002, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE) + 1);
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
    priorityInfo.SetSource(99);
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::INVALID_RESULT));
}

// Positive and raw-value passthrough setter cases only take effect when the priority
// notification feature switch is on (with the switch off the setter is a no-op and keeps
// the default), so the whole cases are compiled out when the switch is off (same pattern
// as notification_helper_test).
#ifdef ANS_FEATURE_PRIORITY_NOTIFICATION
/**
 * @tc.name: SetPriorityNotificationType_00001
 * @tc.desc: Test SetPriorityNotificationType with a type not in VALID_PRIORITY_TYPE_LIST keeps the
 *           raw value (internal channel: the type validation is owned by the third-party entry
 *           NotificationRequest::SetPriorityNotificationType).
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetPriorityNotificationType_00001, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType("TYPE_NOT_IN_VALID_LIST");
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), "TYPE_NOT_IN_VALID_LIST");
}

/**
 * @tc.name: SetPriorityNotificationType_00002
 * @tc.desc: Test SetPriorityNotificationType with empty string keeps the raw empty value.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetPriorityNotificationType_00002, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType("");
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), "");
}

/**
 * @tc.name: SetPriorityNotificationType_00003
 * @tc.desc: Test SetPriorityNotificationType with a type in VALID_PRIORITY_TYPE_LIST takes effect.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetPriorityNotificationType_00003, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    priorityInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::AT_ME);
    EXPECT_EQ(priorityInfo.GetPriorityNotificationType(), NotificationConstant::PriorityNotificationType::AT_ME);
}

/**
 * @tc.name: SetSource_00003
 * @tc.desc: Test SetSource with valid values including range boundaries takes effect.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetSource_00003, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN));
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PARAM_IN));
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE));
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::PUSH_RULE));
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    EXPECT_EQ(priorityInfo.GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

/**
 * @tc.name: SetExpiredTime_00001
 * @tc.desc: Test SetExpiredTime and GetExpiredTime with an absolute time point and 0.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetExpiredTime_00001, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetExpiredTime(1735689600000);
    EXPECT_EQ(priorityInfo.GetExpiredTime(), 1735689600000);
    priorityInfo.SetExpiredTime(0);
    EXPECT_EQ(priorityInfo.GetExpiredTime(), 0);
}

/**
 * @tc.name: SetPriorityInfo_00001
 * @tc.desc: Test SetPriorityInfo copies the priority info into the classification.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, SetPriorityInfo_00001, Function | SmallTest | Level1)
{
    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    priorityInfo.SetExpiredTime(1735689600000);
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));

    NotificationClassification classification("social", "chat");
    classification.SetPriorityInfo(priorityInfo);
    EXPECT_EQ(classification.GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    EXPECT_EQ(classification.GetPriorityInfo().GetExpiredTime(), 1735689600000);
    EXPECT_EQ(classification.GetPriorityInfo().GetSource(),
        static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
}

/**
 * @tc.name: IsPriorityInfoSet_00001
 * @tc.desc: Test the priority dimension flag: default constructed stays unset, the two
 *           string constructor keeps it unset, SetPriorityInfo marks it set, and the
 *           priority only combination (default constructed plus SetPriorityInfo) keeps
 *           the aggregation flag unset through the parcel round trip.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(NotificationClassificationTest, IsPriorityInfoSet_00001, Function | SmallTest | Level1)
{
    NotificationClassification unset;
    EXPECT_EQ(unset.IsPriorityInfoSet(), false);

    NotificationClassification constructed("social", "chat");
    EXPECT_EQ(constructed.IsPriorityInfoSet(), false);

    NotificationClassification::PriorityInfo priorityInfo;
    priorityInfo.SetPriorityNotificationType(NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    priorityInfo.SetExpiredTime(1735689600000);
    priorityInfo.SetSource(static_cast<int32_t>(NotificationConstant::PrioritySourceResult::AI));
    NotificationClassification priorityOnly;
    priorityOnly.SetPriorityInfo(priorityInfo);
    EXPECT_EQ(priorityOnly.IsPriorityInfoSet(), true);
    EXPECT_EQ(priorityOnly.IsClassificationSet(), false);

    Parcel parcel;
    EXPECT_EQ(priorityOnly.Marshalling(parcel), true);
    NotificationClassification *result = NotificationClassification::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->IsPriorityInfoSet(), true);
    EXPECT_EQ(result->IsClassificationSet(), false);
    EXPECT_EQ(result->GetPriorityInfo().GetPriorityNotificationType(),
        NotificationConstant::PriorityNotificationType::URGENT_MESSAGE);
    delete result;
}
#endif  // ANS_FEATURE_PRIORITY_NOTIFICATION
}  // namespace Notification
}  // namespace OHOS