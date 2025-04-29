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
#define protected public
#include "advanced_notification_flow_control_service.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
    constexpr int32_t NON_SYSTEM_APP_UID = 1000;
}
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

/**
 * @tc.number    : FlowControl_00001
 * @tc.name      : Test FlowControl
 * @tc.desc      : Test FlowControl
 */
HWTEST_F(FlowControlServiceTest, FlowControl_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    sptr<Notification> notification = new (std::nothrow) Notification(request);
    auto record = std::make_shared<NotificationRecord>();
    record->request = request;
    record->notification = notification;
    record->isThirdparty = false;
    record->isNeedFlowCtrl = true;
    ErrCode result = ERR_OK;
    int32_t callingUid = DEFAULT_UID;

    // create flow control
    // single app flow control test
    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    // global flow control test
    int gap = MAX_CREATE_NUM_PERSECOND - MAX_CREATE_NUM_PERSECOND_PERAPP;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, false);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);

    // update flow control
    // single app flow control test
    callingUid = DEFAULT_UID;
    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);

    // global flow control test
    gap = MAX_UPDATE_NUM_PERSECOND - MAX_UPDATE_NUM_PERSECOND_PERAPP;
    callingUid = NON_SYSTEM_APP_UID;
    for (int i = 0; i < gap; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    }
    ASSERT_EQ(result, (int)ERR_OK);
    result = FlowControlService::GetInstance()->FlowControl(record, callingUid, true);
    ASSERT_EQ(result, (int)ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
}

/**
 * @tc.name: FlowControl_0002
 * @tc.desc: Test FlowControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_0002, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isNeedFlowCtrl = false;
    auto result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, false);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FlowControl_0003
 * @tc.desc: Test FlowControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, FlowControl_0003, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isNeedFlowCtrl = true;

    sptr<NotificationRequest> req(new NotificationRequest(1));
    req->SetUpdateOnly(true);
    record->request = req;

    ErrCode result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, false);
    ASSERT_EQ(result, ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: PublishFlowCtrl_0001
 * @tc.desc: Test PublishFlowCtrl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, PublishFlowCtrl_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isNeedFlowCtrl = false;
    bool result = FlowControlService::GetInstance()->PublishFlowCtrl(record, DEFAULT_UID);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: PublishGlobalFlowCtrl_0001
 * @tc.desc: Test PublishGlobalFlowCtrl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, PublishGlobalFlowCtrl_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();

    sptr<NotificationRequest> req(new NotificationRequest(1));
    record->isThirdparty = true;
    record->request = req;

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    ErrCode result = ERR_OK;
    for (int i = 0; i < MAX_CREATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, false);
    }

    result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, false);
    ASSERT_EQ(result, ERR_ANS_OVER_MAX_ACTIVE_PERSECOND);
}

/**
 * @tc.name: PublishRecordTimestamp_0001
 * @tc.desc: Test FlowControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, PublishRecordTimestamp_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isThirdparty = true;

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    FlowControlService::GetInstance()->PublishRecordTimestamp(
        record, now, DEFAULT_UID);
    
    auto size = FlowControlService::GetInstance()->flowControlPublishTimestampList_.size();
    ASSERT_EQ(size, 1);
    FlowControlService::GetInstance()->flowControlPublishTimestampList_.clear();
}

/**
 * @tc.name: UpdateFlowCtrl_0001
 * @tc.desc: Test UpdateFlowCtrl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, UpdateFlowCtrl_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isNeedFlowCtrl = false;
    auto result = FlowControlService::GetInstance()->UpdateFlowCtrl(record, DEFAULT_UID);
    ASSERT_EQ(result, ERR_OK);
}

/**
 * @tc.name: UpdateGlobalFlowCtrl_0001
 * @tc.desc: Test UpdateGlobalFlowCtrl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, UpdateGlobalFlowCtrl_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isThirdparty = true;

    sptr<NotificationRequest> req(new NotificationRequest(1));
    req->SetUpdateOnly(true);
    record->request = req;
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();

    ErrCode result = ERR_OK;
    for (int i = 0; i < MAX_UPDATE_NUM_PERSECOND_PERAPP; i++) {
        result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, true);
    }

    result = FlowControlService::GetInstance()->FlowControl(record, DEFAULT_UID, true);
    ASSERT_EQ(result, ERR_ANS_OVER_MAX_UPDATE_PERSECOND);
}

/**
 * @tc.name: UpdateRecordTimestamp_0001
 * @tc.desc: Test FlowControl
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(FlowControlServiceTest, UpdateRecordTimestamp_0001, Function | SmallTest | Level1)
{
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->isThirdparty = true;

    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    FlowControlService::GetInstance()->UpdateRecordTimestamp(
        record, now, DEFAULT_UID);
    
    auto size = FlowControlService::GetInstance()->flowControlUpdateTimestampList_.size();
    ASSERT_EQ(1, size);
    FlowControlService::GetInstance()->flowControlUpdateTimestampList_.clear();
}
}  // namespace Notification
}  // namespace OHOS