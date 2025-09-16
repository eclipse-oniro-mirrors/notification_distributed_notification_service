/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "ans_convert_enum.h"
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
 * @tc.name: AnsConvertTest_001
 * @tc.desc: test ContentTypeJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_001, TestSize.Level1)
{
    NotificationContent::Type outType;
    NotificationNapi::ContentType inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_BASIC_TEXT;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::BASIC_TEXT);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_LONG_TEXT;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::LONG_TEXT);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_MULTILINE;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::MULTILINE);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_PICTURE;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::PICTURE);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_CONVERSATION;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::CONVERSATION);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::LOCAL_LIVE_VIEW);
    inType = NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::ContentTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationContent::Type::LIVE_VIEW);
}


/*
 * @tc.name: AnsConvertTest_002
 * @tc.desc: test ContentTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_002, TestSize.Level1)
{
    NotificationNapi::ContentType outType;
    NotificationContent::Type inType = NotificationContent::Type::BASIC_TEXT;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_BASIC_TEXT);
    inType = NotificationContent::Type::LONG_TEXT;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_LONG_TEXT);
    inType = NotificationContent::Type::MULTILINE;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_MULTILINE);
    inType = NotificationContent::Type::PICTURE;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_PICTURE);
    inType = NotificationContent::Type::CONVERSATION;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_CONVERSATION);
    inType = NotificationContent::Type::LOCAL_LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW);
    inType = NotificationContent::Type::LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::ContentTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::ContentType::NOTIFICATION_CONTENT_LIVE_VIEW);
}

/*
 * @tc.name: AnsConvertTest_003
 * @tc.desc: test SlotTypeJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_003, TestSize.Level1)
{
    NotificationConstant::SlotType outType;
    NotificationNapi::SlotType inType = NotificationNapi::SlotType::SOCIAL_COMMUNICATION;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    inType = NotificationNapi::SlotType::SERVICE_INFORMATION;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::SERVICE_REMINDER);
    inType = NotificationNapi::SlotType::CONTENT_INFORMATION;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::CONTENT_INFORMATION);
    inType = NotificationNapi::SlotType::LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::LIVE_VIEW);
    inType = NotificationNapi::SlotType::CUSTOMER_SERVICE;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::CUSTOMER_SERVICE);
    inType = NotificationNapi::SlotType::EMERGENCY_INFORMATION;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::EMERGENCY_INFORMATION);
    inType = NotificationNapi::SlotType::UNKNOWN_TYPE;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::OTHER);
    inType = NotificationNapi::SlotType::OTHER_TYPES;
    NotificationNapi::AnsEnumUtil::SlotTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::SlotType::OTHER);
}

/*
 * @tc.name: AnsConvertTest_004
 * @tc.desc: test SlotTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_004, TestSize.Level1)
{
    NotificationNapi::SlotType outType;
    NotificationConstant::SlotType inType = NotificationConstant::SlotType::CUSTOM;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::UNKNOWN_TYPE);
    inType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::SOCIAL_COMMUNICATION);
    inType = NotificationConstant::SlotType::SERVICE_REMINDER;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::SERVICE_INFORMATION);
    inType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::CONTENT_INFORMATION);
    inType = NotificationConstant::SlotType::LIVE_VIEW;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::LIVE_VIEW);
    inType = NotificationConstant::SlotType::CUSTOMER_SERVICE;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::CUSTOMER_SERVICE);
    inType = NotificationConstant::SlotType::EMERGENCY_INFORMATION;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::EMERGENCY_INFORMATION);
    inType = NotificationConstant::SlotType::OTHER;
    NotificationNapi::AnsEnumUtil::SlotTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotType::OTHER_TYPES);
}

/*
 * @tc.name: AnsConvertTest_005
 * @tc.desc: test SlotLevelJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_005, TestSize.Level1)
{
    NotificationSlot::NotificationLevel outType;
    NotificationNapi::SlotLevel inType = NotificationNapi::SlotLevel::LEVEL_NONE;
    NotificationNapi::AnsEnumUtil::SlotLevelJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationSlot::NotificationLevel::LEVEL_NONE);
    inType = NotificationNapi::SlotLevel::LEVEL_MIN;
    NotificationNapi::AnsEnumUtil::SlotLevelJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationSlot::NotificationLevel::LEVEL_MIN);
    inType = NotificationNapi::SlotLevel::LEVEL_LOW;
    NotificationNapi::AnsEnumUtil::SlotLevelJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationSlot::NotificationLevel::LEVEL_LOW);
    inType = NotificationNapi::SlotLevel::LEVEL_DEFAULT;
    NotificationNapi::AnsEnumUtil::SlotLevelJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationSlot::NotificationLevel::LEVEL_DEFAULT);
    inType = NotificationNapi::SlotLevel::LEVEL_HIGH;
    NotificationNapi::AnsEnumUtil::SlotLevelJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationSlot::NotificationLevel::LEVEL_HIGH);
}

/*
 * @tc.name: AnsConvertTest_006
 * @tc.desc: test LiveViewStatusJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_006, TestSize.Level1)
{
    NotificationLiveViewContent::LiveViewStatus outType;
    NotificationNapi::LiveViewStatus inType = NotificationNapi::LiveViewStatus::LIVE_VIEW_CREATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE);
    inType = NotificationNapi::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    inType = NotificationNapi::LiveViewStatus::LIVE_VIEW_END;
    NotificationNapi::AnsEnumUtil::LiveViewStatusJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END);
    inType = NotificationNapi::LiveViewStatus::LIVE_VIEW_FULL_UPDATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
}

/*
 * @tc.name: AnsConvertTest_007
 * @tc.desc: test SlotLevelCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_007, TestSize.Level1)
{
    NotificationNapi::SlotLevel outType;
    NotificationSlot::NotificationLevel inType = NotificationSlot::NotificationLevel::LEVEL_NONE;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_NONE);
    inType = NotificationSlot::NotificationLevel::LEVEL_UNDEFINED;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_NONE);
    inType = NotificationSlot::NotificationLevel::LEVEL_MIN;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_MIN);
    inType = NotificationSlot::NotificationLevel::LEVEL_LOW;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_LOW);
    inType = NotificationSlot::NotificationLevel::LEVEL_DEFAULT;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_DEFAULT);
    inType = NotificationSlot::NotificationLevel::LEVEL_HIGH;
    NotificationNapi::AnsEnumUtil::SlotLevelCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SlotLevel::LEVEL_HIGH);
}

/*
 * @tc.name: AnsConvertTest_008
 * @tc.desc: test ReasonCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_008, TestSize.Level1)
{
    int outType;
    int inType = NotificationConstant::DEFAULT_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::DEFAULT_REASON_DELETE));
    inType = NotificationConstant::CLICK_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::CLICK_REASON_REMOVE));
    inType = NotificationConstant::CANCEL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::CANCEL_REASON_REMOVE));
    inType = NotificationConstant::CANCEL_ALL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::CANCEL_ALL_REASON_REMOVE));
    inType = NotificationConstant::ERROR_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::ERROR_REASON_REMOVE));
    inType = NotificationConstant::PACKAGE_CHANGED_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::PACKAGE_CHANGED_REASON_REMOVE));
    inType = NotificationConstant::USER_STOPPED_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::USER_STOPPED_REASON_REMOVE));
    inType = NotificationConstant::APP_CANCEL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_REASON_REMOVE));
    inType = NotificationConstant::APP_CANCEL_ALL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_ALL_REASON_REMOVE));
    inType = NotificationConstant::USER_REMOVED_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::USER_REMOVED_REASON_DELETE));
    inType = NotificationConstant::FLOW_CONTROL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::FLOW_CONTROL_REASON_DELETE));
    inType = NotificationConstant::DISABLE_SLOT_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::DISABLE_SLOT_REASON_DELETE));
    inType = NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::DISABLE_NOTIFICATION_REASON_DELETE));
    inType = NotificationConstant::APP_CANCEL_AS_BUNELE_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_AS_BUNELE_REASON_DELETE));
    inType = NotificationConstant::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType,
        static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_AS_BUNELE_WITH_AGENT_REASON_DELETE));
    inType = NotificationConstant::APP_CANCEL_REMINDER_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_REMINDER_REASON_DELETE));
    inType = NotificationConstant::APP_CANCEL_GROPU_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_GROPU_REASON_DELETE));
    inType = NotificationConstant::APP_REMOVE_GROUP_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_REMOVE_GROUP_REASON_DELETE));
    inType = NotificationConstant::APP_REMOVE_ALL_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_REMOVE_ALL_REASON_DELETE));
    inType = NotificationConstant::APP_REMOVE_ALL_USER_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_REMOVE_ALL_USER_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_EIGHT_HOUR_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_EIGHT_HOUR_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_FOUR_HOUR_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_FOUR_HOUR_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_TEN_MINUTES_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_TEN_MINUTES_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_FIFTEEN_MINUTES_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_FIFTEEN_MINUTES_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_THIRTY_MINUTES_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_THIRTY_MINUTES_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_START_ARCHIVE_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_START_ARCHIVE_REASON_DELETE));
    inType = NotificationConstant::TRIGGER_AUTO_DELETE_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::TRIGGER_AUTO_DELETE_REASON_DELETE));
    inType = NotificationConstant::PACKAGE_REMOVE_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::PACKAGE_REMOVE_REASON_DELETE));
    inType = NotificationConstant::SLOT_ENABLED_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::SLOT_ENABLED_REASON_DELETE));
    inType = NotificationConstant::APP_CANCEL_REASON_OTHER;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_REASON_OTHER));
    inType = NotificationConstant::RECOVER_LIVE_VIEW_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::RECOVER_LIVE_VIEW_DELETE));
    inType = NotificationConstant::DISABLE_NOTIFICATION_FEATURE_REASON_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType,
        static_cast<int32_t>(NotificationNapi::RemoveReason::DISABLE_NOTIFICATION_FEATURE_REASON_DELETE));
    inType = NotificationConstant::DISTRIBUTED_COLLABORATIVE_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::DISTRIBUTED_COLLABORATIVE_DELETE));
    inType = NotificationConstant::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::DISTRIBUTED_COLLABORATIVE_CLICK_DELETE));
    inType = NotificationConstant::APP_CANCEL_REASON_OTHER;
    NotificationNapi::AnsEnumUtil::ReasonCToJS(inType, outType);
    EXPECT_EQ(outType, static_cast<int32_t>(NotificationNapi::RemoveReason::APP_CANCEL_REASON_OTHER));
}

/*
 * @tc.name: AnsConvertTest_009
 * @tc.desc: test DoNotDisturbTypeJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_009, TestSize.Level1)
{
    NotificationConstant::DoNotDisturbType outType;
    NotificationNapi::DoNotDisturbType inType = NotificationNapi::DoNotDisturbType::TYPE_NONE;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::DoNotDisturbType::NONE);
    inType = NotificationNapi::DoNotDisturbType::TYPE_ONCE;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::DoNotDisturbType::ONCE);
    inType = NotificationNapi::DoNotDisturbType::TYPE_DAILY;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::DoNotDisturbType::DAILY);
    inType = NotificationNapi::DoNotDisturbType::TYPE_CLEARLY;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationConstant::DoNotDisturbType::CLEARLY);
}

/*
 * @tc.name: AnsConvertTest_010
 * @tc.desc: test DoNotDisturbTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_010, TestSize.Level1)
{
    NotificationNapi::DoNotDisturbType outType;
    NotificationConstant::DoNotDisturbType inType = NotificationConstant::DoNotDisturbType::NONE;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DoNotDisturbType::TYPE_NONE);
    inType = NotificationConstant::DoNotDisturbType::ONCE;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DoNotDisturbType::TYPE_ONCE);
    inType = NotificationConstant::DoNotDisturbType::DAILY;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DoNotDisturbType::TYPE_DAILY);
    inType = NotificationConstant::DoNotDisturbType::CLEARLY;
    NotificationNapi::AnsEnumUtil::DoNotDisturbTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DoNotDisturbType::TYPE_CLEARLY);
}

/*
 * @tc.name: AnsConvertTest_011
 * @tc.desc: test DeviceRemindTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_011, TestSize.Level1)
{
    NotificationNapi::DeviceRemindType outType;
    NotificationConstant::RemindType inType = NotificationConstant::RemindType::DEVICE_IDLE_DONOT_REMIND;
    NotificationNapi::AnsEnumUtil::DeviceRemindTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DeviceRemindType::IDLE_DONOT_REMIND);
    inType = NotificationConstant::RemindType::DEVICE_IDLE_REMIND;
    NotificationNapi::AnsEnumUtil::DeviceRemindTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DeviceRemindType::IDLE_REMIND);
    inType = NotificationConstant::RemindType::DEVICE_ACTIVE_DONOT_REMIND;
    NotificationNapi::AnsEnumUtil::DeviceRemindTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DeviceRemindType::ACTIVE_DONOT_REMIND);
    inType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    NotificationNapi::AnsEnumUtil::DeviceRemindTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::DeviceRemindType::ACTIVE_REMIND);
}

/*
 * @tc.name: AnsConvertTest_012
 * @tc.desc: test SourceTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_012, TestSize.Level1)
{
    NotificationNapi::SourceType outType;
    NotificationConstant::SourceType inType = NotificationConstant::SourceType::TYPE_NORMAL;
    NotificationNapi::AnsEnumUtil::SourceTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SourceType::TYPE_NORMAL);
    inType = NotificationConstant::SourceType::TYPE_CONTINUOUS;
    NotificationNapi::AnsEnumUtil::SourceTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SourceType::TYPE_CONTINUOUS);
    inType = NotificationConstant::SourceType::TYPE_TIMER;
    NotificationNapi::AnsEnumUtil::SourceTypeCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::SourceType::TYPE_TIMER);
}

/*
 * @tc.name: AnsConvertTest_013
 * @tc.desc: test LiveViewStatusCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_013, TestSize.Level1)
{
    NotificationNapi::LiveViewStatus outType;
    NotificationLiveViewContent::LiveViewStatus inType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_CREATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewStatus::LIVE_VIEW_CREATE);
    inType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewStatus::LIVE_VIEW_INCREMENTAL_UPDATE);
    inType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_END;
    NotificationNapi::AnsEnumUtil::LiveViewStatusCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewStatus::LIVE_VIEW_END);
    inType = NotificationLiveViewContent::LiveViewStatus::LIVE_VIEW_FULL_UPDATE;
    NotificationNapi::AnsEnumUtil::LiveViewStatusCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewStatus::LIVE_VIEW_FULL_UPDATE);
}

/*
 * @tc.name: AnsConvertTest_014
 * @tc.desc: test LiveViewTypesJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_014, TestSize.Level1)
{
    NotificationLocalLiveViewContent::LiveViewTypes outType;
    NotificationNapi::LiveViewTypes inType = NotificationNapi::LiveViewTypes::LIVE_VIEW_ACTIVITY;
    NotificationNapi::AnsEnumUtil::LiveViewTypesJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY);
    inType = NotificationNapi::LiveViewTypes::LIVE_VIEW_INSTANT;
    NotificationNapi::AnsEnumUtil::LiveViewTypesJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT);
    inType = NotificationNapi::LiveViewTypes::LIVE_VIEW_LONG_TERM;
    NotificationNapi::AnsEnumUtil::LiveViewTypesJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_LONG_TERM);
    inType = NotificationNapi::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER;
    NotificationNapi::AnsEnumUtil::LiveViewTypesJSToC(inType, outType);
    EXPECT_EQ(outType, NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER);
}

/*
 * @tc.name: AnsConvertTest_015
 * @tc.desc: test LiveViewTypesCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_015, TestSize.Level1)
{
    NotificationNapi::LiveViewTypes outType;
    NotificationLocalLiveViewContent::LiveViewTypes inType =
        NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_ACTIVITY;
    NotificationNapi::AnsEnumUtil::LiveViewTypesCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewTypes::LIVE_VIEW_ACTIVITY);
    inType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT;
    NotificationNapi::AnsEnumUtil::LiveViewTypesCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewTypes::LIVE_VIEW_INSTANT);
    inType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_LONG_TERM;
    NotificationNapi::AnsEnumUtil::LiveViewTypesCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewTypes::LIVE_VIEW_LONG_TERM);
    inType = NotificationLocalLiveViewContent::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER;
    NotificationNapi::AnsEnumUtil::LiveViewTypesCToJS(inType, outType);
    EXPECT_EQ(outType, NotificationNapi::LiveViewTypes::LIVE_VIEW_INSTANT_BANNER);
}

/*
 * @tc.name: AnsConvertTest_016
 * @tc.desc: test SubscribeTypeJSToC function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_016, TestSize.Level1)
{
    NotificationNapi::SubscribeType inType = NotificationNapi::SubscribeType::BLUETOOTH;
    NotificationConstant::SubscribeType outType;
    auto ret = NotificationNapi::AnsEnumUtil::SubscribeTypeJSToC(inType, outType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(outType, NotificationConstant::SubscribeType::BLUETOOTH);
}

/*
 * @tc.name: AnsConvertTest_017
 * @tc.desc: test SubscribeTypeCToJS function
 * @tc.type: FUNC
 * @tc.require: issueI5UI8T
 */
HWTEST_F(AnsLogTest, AnsConvertTest_017, TestSize.Level1)
{
    NotificationConstant::SubscribeType inType = NotificationConstant::SubscribeType::BLUETOOTH;
    NotificationNapi::SubscribeType outType;
    auto ret = NotificationNapi::AnsEnumUtil::SubscribeTypeCToJS(inType, outType);
    EXPECT_TRUE(ret);
    EXPECT_EQ(outType, NotificationNapi::SubscribeType::BLUETOOTH);
}
}
}
