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

#include <thread>
#include "advanced_notification_flow_control_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class FlowControlServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FlowControlServiceTest::SetUpTestCase() {}

void FlowControlServiceTest::TearDownTestCase() {}

void FlowControlServiceTest::SetUp() {}

void FlowControlServiceTest::TearDown() {}

std::shared_ptr<NotificationRecord> GetCommonNotificationRecord()
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isNeedFlowCtrl = true;
    return record;
}

std::shared_ptr<NotificationRecord> GetLiveviewNotificationRecord()
{
    auto slotType = NotificationConstant::SlotType::LIVE_VIEW;
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetSlotType(slotType);
    auto liveContent = std::make_shared<NotificationLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(liveContent);
    request->SetContent(content);
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isNeedFlowCtrl = true;
    return record;
}

/**
 * @tc.name: FlowControl_100
 * @tc.desc: Test FlowControl when no need to flow control
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_100, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isNeedFlowCtrl = false;
    auto ansStatus = FlowControlService::GetInstance().FlowControl(record, DEFAULT_UID, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);
}

/**
 * @tc.name: FlowControl_200
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_200, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_CREATE_NUM_PERSECOND_PERAPP < MAX_CREATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
        }
        totalCreate += MAX_CREATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_CREATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_300
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_SYSTEM_NORMAL_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_300, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_UPDATE_NUM_PERSECOND_PERAPP < MAX_UPDATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
        }
        totalCreate += MAX_UPDATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_UPDATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_400
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_400, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_CREATE_NUM_PERSECOND_PERAPP < MAX_CREATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
        }
        totalCreate += MAX_CREATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_CREATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_500
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_SYSTEM_LIVEVIEW_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_500, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_UPDATE_NUM_PERSECOND_PERAPP < MAX_UPDATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
        }
        totalCreate += MAX_UPDATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_UPDATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_600
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_600, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_CREATE_NUM_PERSECOND_PERAPP < MAX_CREATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
        }
        totalCreate += MAX_CREATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_CREATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_700
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_THIRD_PART_NORMAL_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_700, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_UPDATE_NUM_PERSECOND_PERAPP < MAX_UPDATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
        }
        totalCreate += MAX_UPDATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_UPDATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_800
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_800, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_CREATE_NUM_PERSECOND_PERAPP < MAX_CREATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
        }
        totalCreate += MAX_CREATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_CREATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_900
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::GLOBAL_THIRD_PART_LIVEVIEW_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_900, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    int32_t index = 1;
    AnsStatus ansStatus;
    uint32_t totalCreate = 0;
    while (totalCreate + MAX_UPDATE_NUM_PERSECOND_PERAPP < MAX_UPDATE_NUM_PERSECOND) {
        for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
            ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
        }
        totalCreate += MAX_UPDATE_NUM_PERSECOND_PERAPP;
        index++;
    }

    int gap = MAX_UPDATE_NUM_PERSECOND - totalCreate;
    for (int i = 0; i < gap; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid + index, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1000
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_SYSTEM_NORMAL_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1000, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1100
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_SYSTEM_NORMAL_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1100, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1200
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1200, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1300
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_SYSTEM_LIVEVIEW_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1300, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = false;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1400
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_THIRD_PART_NORMAL_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1400, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1500
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_THIRD_PART_NORMAL_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1500, Function | SmallTest | Level1)
{
    auto record = GetCommonNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1600
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_CREATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1600, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, false);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @tc.name: FlowControl_1700
 * @tc.desc: Test FlowControl when scene type is FlowControlSceneType::CALLER_THIRD_PART_LIVEVIEW_UPDATE
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_1700, Function | SmallTest | Level1)
{
    auto record = GetLiveviewNotificationRecord();
    record->isThirdparty = true;
    int32_t uid = 1000;
    AnsStatus ansStatus;

    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    }
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_OK);

    ansStatus = FlowControlService::GetInstance().FlowControl(record, uid, true);
    ASSERT_EQ(ansStatus.GetErrCode(), ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
    std::this_thread::sleep_for(std::chrono::seconds(1));
}
}  // namespace Notification
}  // namespace OHOS