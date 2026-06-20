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

#include "ans_inner_errors.h"
#include "ans_service_errors.h"
#include "notification_analytics_util.h"
#include "mock_common_event_manager.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "distributed_device_status.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
std::string GetClientBundleName()
{
    return "test.bundle";
}

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
 * @tc.name: Operation_100
 * @tc.desc: Test Operation.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Operation_100, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("abc");
    deviceTypes.push_back("2in1");
    deviceTypes.push_back("tablet");
    operationMessage.KeyNode(true).SyncPublish("notification_1", deviceTypes);
    operationMessage.ToJson();
    ASSERT_EQ(operationMessage.notificationData.countTime, 4);
    operationMessage.ResetData();
    operationMessage.KeyNode(true).SyncDelete("notification_1");

    operationMessage = HaOperationMessage(true);
    deviceTypes.clear();
    deviceTypes.push_back("abc");
    deviceTypes.push_back("wearable");
    deviceTypes.push_back("headset");
    operationMessage.KeyNode(false).SyncPublish("notification_1", deviceTypes);
    operationMessage.ToJson();
    ASSERT_EQ(operationMessage.liveViewData.countTime, 4);
    ASSERT_EQ(operationMessage.liveViewData.syncWatchHead, 1);
    operationMessage.KeyNode(false).SyncDelete("notification_1");
}

/**
 * @tc.name: Operation_200
 * @tc.desc: Test Operation.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Operation_200, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.notificationData.countTime = 0;
    operationMessage.SyncDelete("2in1", std::string()).SyncClick("2in1").SyncReply("2in1");
    operationMessage.SyncDelete("pcb", std::string()).SyncClick("pcb").SyncReply("pcb");
    operationMessage.ToJson();

    ASSERT_EQ(operationMessage.notificationData.countTime, 3);
    operationMessage.ResetData();

    operationMessage.liveViewData.countTime = 0;
    operationMessage = HaOperationMessage(true);
    operationMessage.ResetData();
    operationMessage.SyncDelete("2in1", std::string()).SyncClick("2in1").SyncReply("2in1");
    operationMessage.SyncDelete("pcb", std::string()).SyncClick("pcb").SyncReply("pcb");
    operationMessage.ToJson();
    ASSERT_EQ(operationMessage.liveViewData.countTime, 3);
}

/**
 * @tc.name: Operation_300
 * @tc.desc: Test Operation.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Operation_300, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.ResetData();
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), false);

    operationMessage.isLiveView_ = true;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), false);

    operationMessage.isLiveView_ = false;
    operationMessage.liveViewData.keyNode++;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), false);

    operationMessage.isLiveView_ = true;
    operationMessage.liveViewData.countTime = 10000;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), true);

    operationMessage.liveViewData.countTime = 10;
    operationMessage.liveViewData.time = 0;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), true);

    operationMessage.isLiveView_ = false;
    operationMessage.notificationData.countTime = 10000;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), true);

    operationMessage.notificationData.countTime = 10;
    operationMessage.notificationData.time = 0;
    ASSERT_EQ(operationMessage.DetermineWhetherToSend(), true);
    operationMessage.ResetData();
}

/**
 * @tc.name: Operation_400
 * @tc.desc: Test Operation.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Operation_400, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.keyNode++;
    NotificationAnalyticsUtil::ReportOperationsDotEvent(operationMessage);
    ASSERT_EQ(operationMessage.liveViewData.keyNode, 0);
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
    flags->SetLockScreenEnabled(NotificationConstant::FlagStatus::OPEN);
    flags->SetBannerEnabled(NotificationConstant::FlagStatus::OPEN);

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
    flags->SetLockScreenEnabled(NotificationConstant::FlagStatus::CLOSE);
    flags->SetBannerEnabled(NotificationConstant::FlagStatus::CLOSE);

    auto ret = NotificationAnalyticsUtil::SetControlFlags(flags, controlFlags);

    ASSERT_EQ(ret, 0);
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
    NotificationAnalyticsUtil::ReportTriggerLiveView({"com.ohos.test"});
    auto res = NotificationAnalyticsUtil::GetReportSlotMessage(
        budleEntryKey, budleEntryValue, reportSlotMessage, userId);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: GetReportSlotMessage_002
 * @tc.desc: Test GetReportSlotMessage_002 when match pattern successfully but not exists in database
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetReportSlotMessage_002, Function | SmallTest | Level1)
{
    std::string budleEntryKey = "ans_bundle_com.example.test20002000__slot_type_5_enabled";
    std::string budleEntryValue = "1";
    ReportSlotMessage reportSlotMessage;
    int32_t userId = 100;
    auto res = NotificationAnalyticsUtil::GetReportSlotMessage(
        budleEntryKey, budleEntryValue, reportSlotMessage, userId);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: NeedReport_300
 * @tc.desc: Test NeedReport when errorCode is ERR_OK and checkfailed is true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, NeedReport_300, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_OK;
    message.checkfailed_ = true;

    auto ret = message.NeedReport();

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: NeedReport_400
 * @tc.desc: Test NeedReport when errorCode is not ERR_OK and checkfailed is true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, NeedReport_400, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_ANS_INNER_INVALID_PARAM;
    message.checkfailed_ = true;

    auto ret = message.NeedReport();

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: Message_001
 * @tc.desc: Test Message with print parameter true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Message_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    std::string testMessage = "Test message";
    message.errorCode_ = ERR_ANS_INNER_INVALID_PARAM;

    auto& ret = message.Message(testMessage, true);

    ASSERT_EQ(message.message_, testMessage);
}

/**
 * @tc.name: Message_002
 * @tc.desc: Test Message with print parameter false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Message_002, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    std::string testMessage = "Test message";
    message.errorCode_ = ERR_ANS_INNER_INVALID_PARAM;

    auto& ret = message.Message(testMessage, false);

    ASSERT_EQ(message.message_, testMessage);
}

/**
 * @tc.name: KeyNode_001
 * @tc.desc: Test KeyNode with true parameter
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, KeyNode_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.keyNode = 0;

    auto& ret = operationMessage.KeyNode(true);

    ASSERT_EQ(operationMessage.liveViewData.keyNode, 1);
}

/**
 * @tc.name: KeyNode_002
 * @tc.desc: Test KeyNode with false parameter
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, KeyNode_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.keyNode = 5;

    auto& ret = operationMessage.KeyNode(false);

    ASSERT_EQ(operationMessage.liveViewData.keyNode, 5);
}

/**
 * @tc.name: ToJson_001
 * @tc.desc: Test ToJson with isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ToJson_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.keyNode = 1;
    operationMessage.liveViewData.syncWatchHead = 1;

    auto jsonStr = operationMessage.ToJson();

    ASSERT_TRUE(jsonStr.find("liveview") != std::string::npos);
}

/**
 * @tc.name: ToJson_002
 * @tc.desc: Test ToJson with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ToJson_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.notificationData.keyNode = 1;
    operationMessage.notificationData.syncWatchHead = 1;

    auto jsonStr = operationMessage.ToJson();

    ASSERT_TRUE(jsonStr.find("notification") != std::string::npos);
}

/**
 * @tc.name: SyncPublish_001
 * @tc.desc: Test SyncPublish with isLiveView true and headset device
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncPublish_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.syncWatchHead = 0;
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("headset");
    deviceTypes.push_back("wearable");

    operationMessage.SyncPublish("test_hash", deviceTypes);

    ASSERT_EQ(operationMessage.liveViewData.syncWatchHead, 1);
}

/**
 * @tc.name: SyncPublish_002
 * @tc.desc: Test SyncPublish with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncPublish_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.notificationData.syncWatchHead = 0;
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("phone");

    operationMessage.SyncPublish("test_hash", deviceTypes);

    ASSERT_EQ(operationMessage.notificationData.syncWatchHead, 0);
}

/**
 * @tc.name: SyncDelete_001
 * @tc.desc: Test SyncDelete with isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncDelete_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("headset");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncDelete("test_hash");

    ASSERT_EQ(operationMessage.liveViewData.dataMap["headset"].hashCodes.size(), 0);
}

/**
 * @tc.name: SyncDelete_002
 * @tc.desc: Test SyncDelete with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncDelete_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("phone");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncDelete("test_hash");

    ASSERT_EQ(operationMessage.notificationData.dataMap["phone"].hashCodes.size(), 0);
}

/**
 * @tc.name: SyncDeleteWithReason_001
 * @tc.desc: Test SyncDelete with deviceType and reason, isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncDeleteWithReason_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("headset");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncDelete("headset", "test_reason");

    ASSERT_EQ(operationMessage.liveViewData.dataMap["headset"].delTime, 1);
}

/**
 * @tc.name: SyncDeleteWithReason_002
 * @tc.desc: Test SyncDelete with deviceType and reason, isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncDeleteWithReason_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("phone");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncDelete("phone", "test_reason");

    ASSERT_EQ(operationMessage.notificationData.dataMap["phone"].delTime, 1);
}

/**
 * @tc.name: SyncClick_001
 * @tc.desc: Test SyncClick with isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncClick_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("headset");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncClick("headset");

    ASSERT_EQ(operationMessage.liveViewData.dataMap["headset"].clickTime, 1);
}

/**
 * @tc.name: SyncClick_002
 * @tc.desc: Test SyncClick with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncClick_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("phone");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncClick("phone");

    ASSERT_EQ(operationMessage.notificationData.dataMap["phone"].clickTime, 1);
}

/**
 * @tc.name: SyncReply_001
 * @tc.desc: Test SyncReply with isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncReply_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("headset");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncReply("headset");

    ASSERT_EQ(operationMessage.liveViewData.dataMap["headset"].replyTime, 1);
}

/**
 * @tc.name: SyncReply_002
 * @tc.desc: Test SyncReply with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SyncReply_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    std::vector<std::string> deviceTypes;
    deviceTypes.push_back("phone");
    operationMessage.SyncPublish("test_hash", deviceTypes);

    operationMessage.SyncReply("phone");

    ASSERT_EQ(operationMessage.notificationData.dataMap["phone"].replyTime, 1);
}

/**
 * @tc.name: ReportTipsEvent_001
 * @tc.desc: Test ReportTipsEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportTipsEvent_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportTipsEvent(request, message));
}

/**
 * @tc.name: ReportPublishFailedEvent_001
 * @tc.desc: Test ReportPublishFailedEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishFailedEvent_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message));
}

/**
 * @tc.name: ReportPublishFailedEvent_002
 * @tc.desc: Test ReportPublishFailedEvent with INT32_MAX sceneId
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishFailedEvent_002, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = INT32_MAX;
    message.branchId_ = 1;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message));
}

/**
 * @tc.name: ReportPublishFailedEvent_003
 * @tc.desc: Test ReportPublishFailedEvent with INT32_MAX branchId
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishFailedEvent_003, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = INT32_MAX;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishFailedEvent(request, message));
}

/**
 * @tc.name: ReportDeleteFailedEvent_003
 * @tc.desc: Test ReportDeleteFailedEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportDeleteFailedEvent_003, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, message));
}

/**
 * @tc.name: ReportDeleteFailedEvent_004
 * @tc.desc: Test ReportDeleteFailedEvent with null agent bundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportDeleteFailedEvent_004, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.errorCode_ = ERR_OK;
    message.checkfailed_ = false;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportDeleteFailedEvent(request, message));
}

/**
 * @tc.name: ReportSAPublishSuccessEvent_001
 * @tc.desc: Test ReportSAPublishSuccessEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportSAPublishSuccessEvent_001, Function | SmallTest | Level1)
{
    int32_t callUid = 1000;
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportSAPublishSuccessEvent(request, callUid));
}

/**
 * @tc.name: ReportPublishWithUserInput_001
 * @tc.desc: Test ReportPublishWithUserInput with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishWithUserInput_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishWithUserInput(request));
}

/**
 * @tc.name: ReportPublishWithUserInput_002
 * @tc.desc: Test ReportPublishWithUserInput without user input button
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishWithUserInput_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishWithUserInput(request));
}

/**
 * @tc.name: ReportPublishSuccessEvent_001
 * @tc.desc: Test ReportPublishSuccessEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishSuccessEvent_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishSuccessEvent(request, message));
}

/**
 * @tc.name: ReportBadgeChange_001
 * @tc.desc: Test ReportBadgeChange with nullptr badgeData
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportBadgeChange_001, Function | SmallTest | Level1)
{
    sptr<BadgeNumberCallbackData> badgeData = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportBadgeChange(badgeData));
}

/**
 * @tc.name: ReportPublishBadge_001
 * @tc.desc: Test ReportPublishBadge with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishBadge_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = nullptr;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishBadge(request));
}

/**
 * @tc.name: ReportPublishBadge_002
 * @tc.desc: Test ReportPublishBadge with badge number <= 0
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportPublishBadge_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetBadgeNumber(0);

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportPublishBadge(request));
}

/**
 * @tc.name: BuildAnsData_002
 * @tc.desc: Test BuildAnsData without unified group info
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BuildAnsData_002, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto flags = std::make_shared<NotificationFlags>();
    request->SetFlags(flags);

    auto ret = NotificationAnalyticsUtil::BuildAnsData(request, message);

    ASSERT_TRUE(ret.find("uid") != std::string::npos);
}

/**
 * @tc.name: BuildExtraInfoWithReq_001
 * @tc.desc: Test BuildExtraInfoWithReq with live view content
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BuildExtraInfoWithReq_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = 1;
    message.errorCode_ = ERR_OK;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto liveViewContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveViewContent);
    request->SetContent(content);

    auto ret = NotificationAnalyticsUtil::BuildExtraInfoWithReq(message, request);

    ASSERT_TRUE(ret.find("scene") != std::string::npos);
}

/**
 * @tc.name: GetFlowOptionByType_001
 * @tc.desc: Test GetFlowOptionByType with MODIFY_ERROR_EVENT_CODE
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetFlowOptionByType_001, Function | SmallTest | Level1)
{
    auto option = NotificationAnalyticsUtil::GetFlowOptionByType(6);

    ASSERT_EQ(option.count, 6);
    ASSERT_EQ(option.time, 60);
}

/**
 * @tc.name: GetFlowOptionByType_002
 * @tc.desc: Test GetFlowOptionByType with default code
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, GetFlowOptionByType_002, Function | SmallTest | Level1)
{
    auto option = NotificationAnalyticsUtil::GetFlowOptionByType(999);

    ASSERT_EQ(option.count, 5);
    ASSERT_EQ(option.time, 60);
}

/**
 * @tc.name: ReportFlowControl_002
 * @tc.desc: Test ReportFlowControl with invalid type
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportFlowControl_002, Function | SmallTest | Level1)
{
    auto res = NotificationAnalyticsUtil::ReportFlowControl(999);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: ReportModifyEvent_001
 * @tc.desc: Test ReportModifyEvent with unFlowControl true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportModifyEvent_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = 1;
    message.errorCode_ = ERR_OK;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportModifyEvent(message, true));
}

/**
 * @tc.name: ReportModifyEvent_002
 * @tc.desc: Test ReportModifyEvent with unFlowControl false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportModifyEvent_002, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = 1;
    message.errorCode_ = ERR_OK;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportModifyEvent(message, false));
}

/**
 * @tc.name: ReportDeleteFailedEvent_005
 * @tc.desc: Test ReportDeleteFailedEvent without request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportDeleteFailedEvent_005, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = 1;
    message.errorCode_ = ERR_OK;
    message.checkfailed_ = false;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportDeleteFailedEvent(message));
}

/**
 * @tc.name: ReportNotificationEvent_001
 * @tc.desc: Test ReportNotificationEvent with Want and eventCode
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ReportNotificationEvent_001, Function | SmallTest | Level1)
{
    EventFwk::Want want;
    want.SetBundle("test_bundle");
    int32_t eventCode = 0;
    std::string reason = "test_reason";

    EXPECT_NO_THROW(NotificationAnalyticsUtil::ReportNotificationEvent(want, eventCode, reason));
}

/**
 * @tc.name: CommonNotificationEvent_001
 * @tc.desc: Test CommonNotificationEvent with nullptr request
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, CommonNotificationEvent_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    sptr<NotificationRequest> request = nullptr;
    int32_t eventCode = 0;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::CommonNotificationEvent(request, eventCode, message));
}

/**
 * @tc.name: DetermineWhetherToSend_001
 * @tc.desc: Test DetermineWhetherToSend with liveView and keyNode
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.keyNode = 1;

    auto ret = operationMessage.DetermineWhetherToSend();

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: DetermineWhetherToSend_002
 * @tc.desc: Test DetermineWhetherToSend with liveView and high countTime
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.countTime = 10000;

    auto ret = operationMessage.DetermineWhetherToSend();

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: DetermineWhetherToSend_003
 * @tc.desc: Test DetermineWhetherToSend with notification and high countTime
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, DetermineWhetherToSend_003, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.notificationData.countTime = 10000;

    auto ret = operationMessage.DetermineWhetherToSend();

    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ResetData_001
 * @tc.desc: Test ResetData with isLiveView true
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ResetData_001, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(true);
    operationMessage.liveViewData.countTime = 100;
    operationMessage.liveViewData.keyNode = 5;

    operationMessage.ResetData();

    ASSERT_EQ(operationMessage.liveViewData.countTime, 0);
    ASSERT_EQ(operationMessage.liveViewData.keyNode, 0);
}

/**
 * @tc.name: ResetData_002
 * @tc.desc: Test ResetData with isLiveView false
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, ResetData_002, Function | SmallTest | Level1)
{
    HaOperationMessage operationMessage = HaOperationMessage(false);
    operationMessage.notificationData.countTime = 100;
    operationMessage.notificationData.keyNode = 5;

    operationMessage.ResetData();

    ASSERT_EQ(operationMessage.notificationData.countTime, 0);
    ASSERT_EQ(operationMessage.notificationData.keyNode, 0);
}

/**
 * @tc.name: Append_001
 * @tc.desc: Test Append method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Append_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.message_ = "Hello";

    auto& ret = message.Append(" World");

    ASSERT_EQ(message.message_, "Hello World");
}

/**
 * @tc.name: BundleName_001
 * @tc.desc: Test BundleName method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BundleName_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    std::string bundleName = "test.bundle";

    auto& ret = message.BundleName(bundleName);

    ASSERT_EQ(message.bundleName_, bundleName);
}

/**
 * @tc.name: AgentBundleName_001
 * @tc.desc: Test AgentBundleName method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AgentBundleName_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    std::string agentBundleName = "test.agent.bundle";

    auto& ret = message.AgentBundleName(agentBundleName);

    ASSERT_EQ(message.agentBundleName_, agentBundleName);
}

/**
 * @tc.name: Path_001
 * @tc.desc: Test Path method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Path_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    std::string path = "/test/path";

    auto& ret = message.Path(path);

    ASSERT_EQ(message.path_, path);
}

/**
 * @tc.name: SceneId_001
 * @tc.desc: Test SceneId method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SceneId_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    uint32_t sceneId = 5;

    auto& ret = message.SceneId(sceneId);

    ASSERT_EQ(message.sceneId_, sceneId);
}

/**
 * @tc.name: BranchId_001
 * @tc.desc: Test BranchId method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, BranchId_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    uint32_t branchId = 3;

    auto& ret = message.BranchId(branchId);

    ASSERT_EQ(message.branchId_, branchId);
}

/**
 * @tc.name: NotificationId_001
 * @tc.desc: Test NotificationId method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, NotificationId_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    int32_t notificationId = 123;

    auto& ret = message.NotificationId(notificationId);

    ASSERT_EQ(message.notificationId_, notificationId);
}

/**
 * @tc.name: SlotType_001
 * @tc.desc: Test SlotType method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, SlotType_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    int32_t slotType = 1;

    auto& ret = message.SlotType(slotType);

    ASSERT_EQ(message.slotType_, slotType);
}

/**
 * @tc.name: Build_001
 * @tc.desc: Test Build method
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, Build_001, Function | SmallTest | Level1)
{
    HaMetaMessage message;
    message.sceneId_ = 1;
    message.branchId_ = 2;
    message.errorCode_ = ERR_OK;
    message.message_ = "test";

    auto ret = message.Build();

    ASSERT_TRUE(ret.find("1") != std::string::npos);
    ASSERT_TRUE(ret.find("2") != std::string::npos);
    ASSERT_TRUE(ret.find("test") != std::string::npos);
}

/**
 * @tc.name: AddLiveViewSuccessNum_001
 * @tc.desc: Test AddLiveViewSuccessNum with existing bundle
 * @tc.type:: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AddLiveViewSuccessNum_001, Function | SmallTest | Level1)
{
    std::string bundle = "com.example.app#TAXI";
    int32_t status = 0;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::AddLiveViewSuccessNum(bundle, status));
}

/**
 * @tc.name: AddLiveViewFailedNum_001
 * @tc.desc: Test AddLiveViewFailedNum with existing bundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AddLiveViewFailedNum_001, Function | SmallTest | Level1)
{
    std::string bundle = "com.example.app#TAXI";
    int32_t status = 0;

    EXPECT_NO_THROW(NotificationAnalyticsUtil::AddLiveViewFailedNum(bundle, status));
}

/**
 * @tc.name: AddLocalLiveViewSuccessNum_001
 * @tc.desc: Test AddLocalLiveViewSuccessNum with existing bundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AddLocalLiveViewSuccessNum_001, Function | SmallTest | Level1)
{
    std::string bundle = "com.example.app#-99";

    EXPECT_NO_THROW(NotificationAnalyticsUtil::AddLocalLiveViewSuccessNum(bundle));
}

/**
 * @tc.name: AddLocalLiveViewFailedNum_001
 * @tc.desc: Test AddLocalLiveViewFailedNum with existing bundle
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, AddLocalLiveViewFailedNum_001, Function | SmallTest | Level1)
{
    std::string bundle = "com.example.app#-99";

    EXPECT_NO_THROW(NotificationAnalyticsUtil::AddLocalLiveViewFailedNum(bundle));
}

/**
 * @tc.name: MakeRequestBundle_001
 * @tc.desc: Test MakeRequestBundle with empty bundle names
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, MakeRequestBundle_001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();

    NotificationAnalyticsUtil::MakeRequestBundle(request);

    ASSERT_EQ(request->GetCreatorBundleName(), "test.bundle");
}

/**
 * @tc.name: MakeRequestBundle_002
 * @tc.desc: Test MakeRequestBundle with existing bundle names
 * @tc.type: FUNC
 */
HWTEST_F(NotificationAnalyticsUtilTest, MakeRequestBundle_002, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetOwnerBundleName("owner.bundle");
    request->SetCreatorBundleName("creator.bundle");

    NotificationAnalyticsUtil::MakeRequestBundle(request);

    ASSERT_EQ(request->GetOwnerBundleName(), "owner.bundle");
    ASSERT_EQ(request->GetCreatorBundleName(), "creator.bundle");
}

/**
 * @tc.name: EventSceneId_SCENE_34_001
 * @tc.desc: Test EventSceneId::SCENE_34 exists and can be used
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationAnalyticsUtilTest, EventSceneId_SCENE_34_001, Function | SmallTest | Level1)
{
    HaMetaMessage message(EventSceneId::SCENE_34, EventBranchId::BRANCH_0);
    ASSERT_EQ(message.sceneId_, static_cast<uint32_t>(EventSceneId::SCENE_34));
    ASSERT_EQ(message.branchId_, static_cast<uint32_t>(EventBranchId::BRANCH_0));
}

/**
 * @tc.name: EventSceneId_SCENE_34_002
 * @tc.desc: Test HaMetaMessage with SCENE_34 for IsBannerEnabled scenario
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationAnalyticsUtilTest, EventSceneId_SCENE_34_002, Function | SmallTest | Level1)
{
    HaMetaMessage message(EventSceneId::SCENE_34, EventBranchId::BRANCH_0);
    std::string errMessage = "not in profile,  bundleName :testBundle";
    message.Message(errMessage);
    ASSERT_EQ(message.sceneId_, static_cast<uint32_t>(EventSceneId::SCENE_34));
    ASSERT_TRUE(message.message_.find("testBundle") != std::string::npos);
}
}
}
