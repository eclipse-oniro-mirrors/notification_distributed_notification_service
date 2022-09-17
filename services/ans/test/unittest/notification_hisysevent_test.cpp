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

#include <gtest/gtest.h>
#include <numeric>
#include "event_report.h"
#include "notification_constant.h"
#include "notification_content.h"
#define private public
#define protected public
#include "notification.h"
#undef private
#undef protected

namespace OHOS {
namespace Notification {
using namespace testing::ext;

namespace {
const std::string TEST_CREATER_BUNDLE_NAME = "creater";
const std::string TEST_BUNDLE_OPTION_BUNDLE_NAME = "bundleName";
const std::string TEST_NOTIFICATION_LABEL = "notificationLabel";
constexpr int32_t TEST_NOTIFICATION_ID = 1;
constexpr int32_t TEST_BUNDLE_OPTION_UID = 100;
constexpr int32_t TEST_USER_ID = 1000;
constexpr int32_t TEST_ERROR_CODE = 22;
} // namespace

class NotificationHisyseventTest : public testing::Test {
public:
    NotificationHisyseventTest()
    {}
    ~NotificationHisyseventTest()
    {}

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NotificationHisyseventTest::SetUpTestCase(void)
{}

void NotificationHisyseventTest::TearDownTestCase(void)
{}

void NotificationHisyseventTest::SetUp(void)
{}

void NotificationHisyseventTest::TearDown(void)
{}

/**
 * @tc.name: SendSubscriberErrorSysEvent_0100
 * @tc.desc: Send "SUBSCRIBE_ERROR" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendSubscriberErrorSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendSubscriberErrorSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.pid = getpid();
    eventInfo.uid = getuid();
    eventInfo.errCode = TEST_ERROR_CODE;
    EventReport::SendHiSysEvent(SUBSCRIBE_ERROR, eventInfo);

    eventInfo.userId = TEST_USER_ID;
    std::vector<std::string> appNames = {"app1_1", "app1_2", "app1_3"};
    eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
        [appNames](std::string bundleName, const std::string &str) {
            return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
        });
    EventReport::SendHiSysEvent(SUBSCRIBE_ERROR, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.GetDeviceId();
    EXPECT_EQ(result, deviceId);

    GTEST_LOG_(INFO) << "SendSubscriberErrorSysEvent_0100 end";
}

/**
 * @tc.name: SendEnableNotificationErrorSysEvent_0100
 * @tc.desc: Send "ENABLE_NOTIFICATION_ERROR" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendEnableNotificationErrorSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendEnableNotificationErrorSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = getuid();
    eventInfo.enable = true;
    eventInfo.errCode = TEST_ERROR_CODE;
    EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_ERROR, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    int32_t notificationId =5;
    Notification notificationTest(deviceId, request);
    NotificationRequest notificationRequest(notificationId);
    pid_t myPid = notificationRequest.GetCreatorPid();
    notificationRequest.SetCreatorPid(myPid);
    auto result = notificationTest.GetPid();
    EXPECT_EQ(result, myPid);

    GTEST_LOG_(INFO) << "SendEnableNotificationErrorSysEvent_0100 end";
}

/**
 * @tc.name: SendEnableNotificationSlotErrorSysEvent_0100
 * @tc.desc: Send "ENABLE_NOTIFICATION_SLOT_ERROR" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendEnableNotificationSlotErrorSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendEnableNotificationSlotErrorSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = getuid();
    eventInfo.enable = false;
    eventInfo.slotType = NotificationConstant::SERVICE_REMINDER;
    eventInfo.errCode = TEST_ERROR_CODE;
    EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT_ERROR, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.IsUnremovable();
    EXPECT_EQ(result, false);

    GTEST_LOG_(INFO) << "SendEnableNotificationSlotErrorSysEvent_0100 end";
}

/**
 * @tc.name: SendPublishErrorSysEvent_0100
 * @tc.desc: Send "SUBSCRIBE_ERROR" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendPublishErrorSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendPublishErrorSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.notificationId = TEST_NOTIFICATION_ID;
    eventInfo.contentType = static_cast<int32_t>(NotificationContent::Type::LONG_TEXT);
    eventInfo.bundleName = TEST_CREATER_BUNDLE_NAME;
    eventInfo.userId = TEST_USER_ID;
    eventInfo.errCode = TEST_ERROR_CODE;
    EventReport::SendHiSysEvent(PUBLISH_ERROR, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.IsGroup();
    EXPECT_EQ(result, false);

    GTEST_LOG_(INFO) << "SendPublishErrorSysEvent_0100 end";
}

/**
 * @tc.name: SendFlowControlOccurSysEvent_0100
 * @tc.desc: Send "FLOW_CONTROL_OCCUR" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendFlowControlOccurSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendFlowControlOccurSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.notificationId = TEST_NOTIFICATION_ID;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = TEST_BUNDLE_OPTION_UID;
    EventReport::SendHiSysEvent(FLOW_CONTROL_OCCUR, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.IsFloatingIcon();
    EXPECT_EQ(result, false);

    GTEST_LOG_(INFO) << "SendFlowControlOccurSysEvent_0100 end";
}

/**
 * @tc.name: SendSubscribeSysEvent_0100
 * @tc.desc: Send "SUBSCRIBE" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendSubscribeSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendSubscribeSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.pid = getpid();
    eventInfo.uid = getuid();
    EventReport::SendHiSysEvent(SUBSCRIBE, eventInfo);

    eventInfo.userId = TEST_USER_ID;
    std::vector<std::string> appNames = {"app1_1", "app1_2", "app1_3"};
    eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
        [appNames](std::string bundleName, const std::string &str) {
            return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
        });
    EventReport::SendHiSysEvent(SUBSCRIBE, eventInfo);

    std::vector<std::string> anotherBundle = {"app"};
    eventInfo.bundleName = std::accumulate(anotherBundle.begin(), anotherBundle.end(), std::string(""),
        [anotherBundle](std::string bundleName, const std::string &str) {
            return (str == anotherBundle.front()) ? (bundleName + str) : (bundleName + "," + str);
        });
    EventReport::SendHiSysEvent(SUBSCRIBE, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.MarshallingBool(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendSubscribeSysEvent_0100 end";
}

/**
 * @tc.name: SendUnSubscribeSysEvent_0100
 * @tc.desc: Send "UNSUBSCRIBE" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendUnSubscribeSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendUnSubscribeSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.pid = getpid();
    eventInfo.uid = getuid();
    eventInfo.userId = TEST_USER_ID;
    std::vector<std::string> appNames = {"app1_1", "app1_2", "app1_3"};
    eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
        [appNames](std::string bundleName, const std::string &str) {
            return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
        });
    EventReport::SendHiSysEvent(UNSUBSCRIBE, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.MarshallingInt32(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendUnSubscribeSysEvent_0100 end";
}

/**
 * @tc.name: SendEnableNotificationSysEvent_0100
 * @tc.desc: Send "ENABLE_NOTIFICATION" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendEnableNotificationSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendEnableNotificationSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = getuid();
    eventInfo.enable = true;
    EventReport::SendHiSysEvent(ENABLE_NOTIFICATION, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.MarshallingInt64(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendEnableNotificationSysEvent_0100 end";
}

/**
 * @tc.name: SendEnableNotificationSlotSysEvent_0100
 * @tc.desc: Send "ENABLE_NOTIFICATION_SLOT" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendEnableNotificationSlotSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendEnableNotificationSlotSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = getuid();
    eventInfo.enable = true;
    eventInfo.slotType = NotificationConstant::CONTENT_INFORMATION;
    EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.MarshallingParcelable(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendEnableNotificationSlotSysEvent_0100 end";
}

/**
 * @tc.name: SendPublishSysEvent_0100
 * @tc.desc: Send "PUBLISH" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendPublishSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendPublishSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.notificationId = TEST_NOTIFICATION_ID;
    eventInfo.contentType = static_cast<int32_t>(NotificationContent::Type::LONG_TEXT);
    eventInfo.bundleName = TEST_CREATER_BUNDLE_NAME;
    eventInfo.userId = TEST_USER_ID;
    EventReport::SendHiSysEvent(PUBLISH, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.Marshalling(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendPublishSysEvent_0100 end";
}

/**
 * @tc.name: SendCancelSysEvent_0100
 * @tc.desc: Send "CANCEL" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendCancelSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendCancelSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.notificationId = TEST_NOTIFICATION_ID;
    eventInfo.notificationLabel = TEST_NOTIFICATION_LABEL;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = TEST_BUNDLE_OPTION_UID;
    EventReport::SendHiSysEvent(CANCEL, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    Parcel p;
    Notification notificationTest(deviceId, request);
    auto result = notificationTest.ReadFromParcel(p);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "SendCancelSysEvent_0100 end";
}

/**
 * @tc.name: SendRemoveSysEvent_0100
 * @tc.desc: Send "REMOVE" hisysevent.
 * @tc.type: FUNC
 * @tc.require: I582Y4
 */
HWTEST_F(NotificationHisyseventTest, SendRemoveSysEvent_0100, Level1)
{
    GTEST_LOG_(INFO) << "SendRemoveSysEvent_0100 start";

    EventInfo eventInfo;
    eventInfo.notificationId = TEST_NOTIFICATION_ID;
    eventInfo.notificationLabel = TEST_NOTIFICATION_LABEL;
    eventInfo.bundleName = TEST_BUNDLE_OPTION_BUNDLE_NAME;
    eventInfo.uid = TEST_BUNDLE_OPTION_UID;
    EventReport::SendHiSysEvent(REMOVE, eventInfo);
    std::string deviceId = "123";
    sptr<NotificationRequest> request = nullptr;
    std::vector<int64_t> style = {1};
    Notification notificationTest(deviceId, request);
    notificationTest.SetVibrationStyle(style);
    auto result = notificationTest.GetVibrationStyle();
    EXPECT_EQ(result, style);

    GTEST_LOG_(INFO) << "SendRemoveSysEvent_0100 end";
}
}  // namespace Notification
}  // namespace OHOS