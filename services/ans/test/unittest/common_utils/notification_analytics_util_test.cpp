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

#include "notification_analytics_util.h"
#include "mock_common_event_manager.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "distributed_device_status.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class NotificationAnalyticsUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: NeedReport_100
 * @tc.desc: Test NeedReport when error code is ok and checkfailed is true.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, NeedReport_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_OK;

    auto ret = message.NeedReport();

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: NeedReport_200
 * @tc.desc: Test NeedReport.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, NeedReport_200, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.checkfailed_ = false;

    auto ret = message.NeedReport();

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: Checkfailed_100
 * @tc.desc: Test Checkfailed when default is true.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Checkfailed_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    bool checkfailed = false;

    message.Checkfailed(checkfailed);

    ASSERT_FALSE(message.checkfailed_);
}

/**
 * @tc.name: TypeCode_100
 * @tc.desc: Test TypeCode when default is -1.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, TypeCode_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    int32_t typeCode = 0;

    message.TypeCode(typeCode);

    ASSERT_EQ(message.typeCode_, 0);
}

/**
 * @tc.name: GetMessage_100
 * @tc.desc: Test GetMessage.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetMessage_100, Function | SmallTest | Level1)
{
    std::string expect = "test";
    HaMetaMessage message;
    message.message_ = expect;

    auto ret = message.GetMessage();

    ASSERT_EQ(ret, expect);
}

/**
 * @tc.name: DeleteReason_100
 * @tc.desc: Test DeleteReason when default is -1.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DeleteReason_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    int32_t deleteReason = 0;

    message.DeleteReason(deleteReason);

    ASSERT_EQ(message.deleteReason_, deleteReason);
}

/**
 * @tc.name: SyncWatch_100
 * @tc.desc: Test SyncWatch.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncWatch_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    bool isLiveView = false;
    message.SyncWatch(isLiveView);
    isLiveView = true;
    message.SyncWatch(isLiveView);

    ASSERT_EQ(message.syncLiveViewWatch_, 1);
    ASSERT_EQ(message.syncWatch_, 1);
}

/**
 * @tc.name: SyncHeadSet_100
 * @tc.desc: Test SyncHeadSet.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncHeadSet_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    bool isLiveView = false;
    message.SyncHeadSet(isLiveView);
    isLiveView = true;
    message.SyncHeadSet(isLiveView);

    ASSERT_EQ(message.syncLiveViewHeadSet_, 1);
    ASSERT_EQ(message.syncHeadSet_, 1);
}

/**
 * @tc.name: SyncWatchHeadSet_100
 * @tc.desc: Test SyncWatchHeadSet.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncWatchHeadSet_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    bool isLiveView = false;
    message.SyncWatchHeadSet(isLiveView);
    isLiveView = true;
    message.SyncWatchHeadSet(isLiveView);

    ASSERT_EQ(message.syncLiveViewWatchHeadSet_, 1);
    ASSERT_EQ(message.syncWatchHeadSet_, 1);
}

/**
 * @tc.name: KeyNode_100
 * @tc.desc: Test KeyNode.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, KeyNode_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    bool isKeyNode = false;
    message.KeyNode(isKeyNode);
    ASSERT_EQ(message.keyNode_, 0);

    isKeyNode = true;
    message.KeyNode(isKeyNode);
    ASSERT_EQ(message.keyNode_, 1);
}

/**
 * @tc.name: DelByWatch_100
 * @tc.desc: Test DelByWatch.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DelByWatch_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    bool isLiveView = false;
    message.DelByWatch(isLiveView);
    isLiveView = true;
    message.DelByWatch(isLiveView);

    ASSERT_EQ(message.liveViewDelByWatch_, 1);
    ASSERT_EQ(message.delByWatch_, 1);
}

/**
 * @tc.name: ClickByWatch_100
 * @tc.desc: Test ClickByWatch.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ClickByWatch_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    message.ClickByWatch();

    ASSERT_EQ(message.clickByWatch_, 1);
}

/**
 * @tc.name: ReplyByWatch_100
 * @tc.desc: Test ReplyByWatch.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReplyByWatch_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;

    message.ReplyByWatch();

    ASSERT_EQ(message.replyByWatch_, 1);
}

/**
 * @tc.name: ReportDeleteFailedEvent_100
 * @tc.desc: Test ReportDeleteFailedEvent.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportDeleteFailedEvent_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_OK;
    message.checkfailed_ = false;
    std::string bundle = "bundle";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto agentBundleOption = std::make_shared<NotificationBundleOption>(bundle, DEFAULT_UID);
    request->SetAgentBundle(agentBundleOption);

    NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, message);

    ASSERT_EQ(message.agentBundleName_, bundle);
}

/**
 * @tc.name: ReportDeleteFailedEvent_200
 * @tc.desc: Test ReportDeleteFailedEvent when no need to report.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportDeleteFailedEvent_200, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_OK;
    message.checkfailed_ = true;
    std::string bundle = "bundle";
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto agentBundleOption = std::make_shared<NotificationBundleOption>(bundle, DEFAULT_UID);
    request->SetAgentBundle(agentBundleOption);

    NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, message);

    ASSERT_NE(message.agentBundleName_, bundle);
}

/**
 * @tc.name: BuildAnsData_100
 * @tc.desc: Test BuildAnsData when including .
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BuildAnsData_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto unifiedGroupInfo = std::make_shared<NotificationUnifiedGroupInfo>();
    auto extraInfo = std::make_shared<AAFwk::WantParams>();
    AAFwk::WantParams pushData;
    pushData.SetParam("msgId", AAFwk::String::Box("msgId"));
    pushData.SetParam("mcMsgId", AAFwk::String::Box("mcMsgId"));
    extraInfo->SetParam("pushData", AAFwk::WantParamWrapper::Box(pushData));
    unifiedGroupInfo->SetExtraInfo(extraInfo);
    request->SetUnifiedGroupInfo(unifiedGroupInfo);
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);

    auto ret = NotificationAnalyticsUtil::BuildAnsData(request, message);

    ASSERT_TRUE(ret.find("msgId") != std::string::npos);
    ASSERT_TRUE(ret.find("mcMsgId") != std::string::npos);
}

/**
 * @tc.name: GetDeviceStatus_100
 * @tc.desc: Test GetDeviceStatus.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetDeviceStatus_100, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    std::string deviceType = "phone";
    std::bitset<DistributedDeviceStatus::STATUS_SIZE> bitStatus;
    request->AdddeviceStatu(deviceType, bitStatus.bitset<DistributedDeviceStatus::STATUS_SIZE>::to_string());

    auto ret = NotificationAnalyticsUtil::GetDeviceStatus(request);

    ASSERT_TRUE(ret.find("phone") != std::string::npos);
}

/**
 * @tc.name: SetControlFlags_100
 * @tc.desc: Test SetControlFlags when set controlFlags.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SetControlFlags_100, Function | SmallTest | Level1)
{
    auto flags = std::make_shared<NotificationFlags>();
    uint32_t controlFlags = 0;
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetLockScreenVisblenessEnabled(true);
    flags->SetBannerEnabled(true);

    auto ret = NotificationAnalyticsUtil::SetControlFlags(flags, controlFlags);

    ASSERT_EQ(ret, (0b1111 << 10));
}

/**
 * @tc.name: SetControlFlags_200
 * @tc.desc: Test SetControlFlags when clear controlFlags.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SetControlFlags_200, Function | SmallTest | Level1)
{
    auto flags = std::make_shared<NotificationFlags>();
    uint32_t controlFlags = 0b1111 << 10;
    flags->SetSoundEnabled(NotificationConstant::FlagStatus::CLOSE);
    flags->SetVibrationEnabled(NotificationConstant::FlagStatus::CLOSE);
    flags->SetLockScreenVisblenessEnabled(false);
    flags->SetBannerEnabled(false);

    auto ret = NotificationAnalyticsUtil::SetControlFlags(flags, controlFlags);

    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: DetermineWhetherToSend_100
 * @tc.desc: Test DetermineWhetherToSend when key node is not 0.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_100, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::LIVE_VIEW;
    HaMetaMessage::keyNode_ = 1;

    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_TRUE(ret);
    HaMetaMessage::keyNode_ = 0;
}

/**
 * @tc.name: DetermineWhetherToSend_200
 * @tc.desc: Test DetermineWhetherToSend when slot type is LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_200, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::LIVE_VIEW;
    HaMetaMessage::keyNode_ = 0;
    HaMetaMessage::liveViewTime_ = 0;

    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_TRUE(ret);
    HaMetaMessage::liveViewTime_ = NotificationAnalyticsUtil::GetCurrentTime();
}

/**
 * @tc.name: DetermineWhetherToSend_300
 * @tc.desc: Test DetermineWhetherToSend when slot type is LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_300, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::LIVE_VIEW;
    HaMetaMessage::keyNode_ = 0;
    HaMetaMessage::syncLiveViewWatch_ = 1000;

    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_TRUE(ret);
    HaMetaMessage::syncLiveViewWatch_ = 0;
}

/**
 * @tc.name: DetermineWhetherToSend_400
 * @tc.desc: Test DetermineWhetherToSend when slot type is LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_400, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::LIVE_VIEW;
    HaMetaMessage::keyNode_ = 0;

    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: DetermineWhetherToSend_500
 * @tc.desc: Test DetermineWhetherToSend when slot type is not LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_500, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    HaMetaMessage::keyNode_ = 0;
    HaMetaMessage::time_ = 0;
    
    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_TRUE(ret);
    HaMetaMessage::time_ = NotificationAnalyticsUtil::GetCurrentTime();
}

/**
 * @tc.name: DetermineWhetherToSend_600
 * @tc.desc: Test DetermineWhetherToSend when slot type is not LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_600, Function | SmallTest | Level1)
{
    uint32_t slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    HaMetaMessage::keyNode_ = 0;
    HaMetaMessage::syncWatch_ = 1000;
    
    auto ret = NotificationAnalyticsUtil::DetermineWhetherToSend(slotType);

    ASSERT_TRUE(ret);
    HaMetaMessage::syncWatch_ = 0;
}

/**
 * @tc.name: BuildAnsData_200
 * @tc.desc: Test BuildAnsData when slot type is LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BuildAnsData_200, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.slotType_ = NotificationConstant::SlotType::LIVE_VIEW;

    auto ret = NotificationAnalyticsUtil::BuildAnsData(message);

    ASSERT_TRUE(ret.find("keyNode") != std::string::npos);
}

/**
 * @tc.name: BuildAnsData_300
 * @tc.desc: Test BuildAnsData when slot type is not LIVE_VIEW.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BuildAnsData_300, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.slotType_ = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;

    auto ret = NotificationAnalyticsUtil::BuildAnsData(message);

    ASSERT_FALSE(ret.find("keyNode") != std::string::npos);
}

/**
 * @tc.name: AggregateLiveView_001
 * @tc.desc: Test AggregateLiveView
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AggregateLiveView_001, Function | SmallTest | Level1)
{
    std::string bundle = "com.example.app#TAXI";
    int32_t status = 0;

    NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle, status);
    NotificationAnalyticsUtil::AddLiveViewSuccessNum(bundle, status);
    bundle = "com.example.app2#-99";
    NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle);
    NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle);
    ReportCache reportCache = NotificationAnalyticsUtil::AggregateLiveView();

    EXPECT_EQ(reportCache.eventCode, 7);
    std::string ansData = reportCache.want.GetStringParam("ansData");
    nlohmann::json jsonData = nlohmann::json::parse(ansData);
    EXPECT_TRUE(jsonData["data"].is_string());
    EXPECT_TRUE(jsonData["startTime"].is_number_integer());
    EXPECT_TRUE(jsonData["endTime"].is_number_integer());
}

/**
 * @tc.name: ReportFlowControl_001
 * @tc.desc: Test ReportFlowControl_001
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportFlowControl_001, Function | SmallTest | Level1)
{
    auto res = NotificationAnalyticsUtil::ReportFlowControl(0);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: RemoveExpired_001
 * @tc.desc: Test RemoveExpired_001
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, RemoveExpired_001, Function | SmallTest | Level1)
{
    std::list<std::chrono::system_clock::time_point> list;
    auto now = std::chrono::system_clock::now();
    list.push_back(now);
    EXPECT_EQ(list.size(), 1);
    
    NotificationAnalyticsUtil::RemoveExpired(list, now, 100);
    EXPECT_EQ(list.size(), 1);
    
    NotificationAnalyticsUtil::RemoveExpired(list, now, -1);
    EXPECT_EQ(list.size(), 0);
}

/**
 * @tc.name: ReportSlotEnable_001
 * @tc.desc: Test ReportSlotEnable_001
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportSlotEnable_001, Function | SmallTest | Level1)
{
    NotificationAnalyticsUtil::GetAllSlotMessageCache(100);
    for (auto i = 0; i <= 20; ++i) {
        NotificationAnalyticsUtil::ReportSlotEnable();
    }
    auto res = NotificationAnalyticsUtil::ReportSlotEnable();
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetReportSlotMessage_001
 * @tc.desc: Test GetReportSlotMessage_001
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetReportSlotMessage_001, Function | SmallTest | Level1)
{
    std::string budleEntryKey = "1_1_1_1_1_1_1";
    std::string budleEntryValue = "1";
    ReportSlotMessage reportSlotMessage;
    int32_t userId = 1;
    auto res = NotificationAnalyticsUtil::GetReportSlotMessage(
        budleEntryKey, budleEntryValue, reportSlotMessage, userId);
    EXPECT_FALSE(res);
}
}
}