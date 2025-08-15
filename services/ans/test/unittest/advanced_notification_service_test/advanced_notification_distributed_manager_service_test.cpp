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

#include <thread>
#include "gtest/gtest.h"

#define private public

#include "advanced_notification_service.h"
#include "advanced_datashare_helper.h"
#include "notification_check_request.h"
#include "notification_constant.h"

#include "ans_ut_constant.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "mock_accesstoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Notification {

class AdvancedNotificationDistMgrServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    static sptr<AdvancedNotificationService> advancedNotificationService_;
};

sptr<AdvancedNotificationService> AdvancedNotificationDistMgrServiceTest::advancedNotificationService_ = nullptr;

void AdvancedNotificationDistMgrServiceTest::SetUpTestCase() {}

void AdvancedNotificationDistMgrServiceTest::TearDownTestCase() {}

void AdvancedNotificationDistMgrServiceTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";

    advancedNotificationService_ = new (std::nothrow) AdvancedNotificationService();

    GTEST_LOG_(INFO) << "SetUp end";
}

void AdvancedNotificationDistMgrServiceTest::TearDown()
{
    advancedNotificationService_ = nullptr;
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.name: SetDistributedEnabledBySlot_100
 * @tc.desc: Test SetDistributedEnabledBySlot when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedEnabledBySlot_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    int32_t slotTypeInt = 5;
    std::string deviceType = "";
    bool enabled = false;
    auto ret = advancedNotificationService_->SetDistributedEnabledBySlot(slotTypeInt, deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: IsDistributedEnabledBySlot_100
 * @tc.desc: Test IsDistributedEnabledBySlot when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, IsDistributedEnabledBySlot_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    int32_t slotTypeInt = 5;
    std::string deviceType = "";
    bool enabled = false;

    auto ret = advancedNotificationService_->IsDistributedEnabledBySlot(slotTypeInt, deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: IsDistributedEnabledBySlot_200
 * @tc.desc: Test IsDistributedEnabledBySlot when caller has no permission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, IsDistributedEnabledBySlot_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    int32_t slotTypeInt = 5;
    std::string deviceType = "";
    bool enabled = false;

    auto ret = advancedNotificationService_->IsDistributedEnabledBySlot(slotTypeInt, deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: IsDistributedEnabledBySlot_300
 * @tc.desc: Test IsDistributedEnabledBySlot when succeed to call.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, IsDistributedEnabledBySlot_300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    int32_t slotTypeInt = 5;
    std::string deviceType = "testType";
    bool enabled = false;

    auto ret = advancedNotificationService_->IsDistributedEnabledBySlot(slotTypeInt, deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetTargetDeviceStatus_100
 * @tc.desc: Test GetTargetDeviceStatus when caller is not subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetTargetDeviceStatus_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    std::string deviceType = "testType";
    int32_t status = 5;

    auto ret = advancedNotificationService_->GetTargetDeviceStatus(deviceType, status);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: DistributeOperationParamCheck_100
 * @tc.desc: Test DistributeOperationParamCheck when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperationParamCheck_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("testHashCode");
    sptr<IAnsOperationCallback> callback = nullptr;

    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: DistributeOperationParamCheck_200
 * @tc.desc: Test DistributeOperationParamCheck when invalid operationType.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperationParamCheck_200, Function | SmallTest | Level1)
{
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("hashCode");
    operationInfo->SetOperationType(static_cast<OperationType>(5));
    sptr<IAnsOperationCallback> callback = nullptr;
    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DistributeOperation_100
 * @tc.desc: Test DistributeOperation when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("testHashCode");
    sptr<IAnsOperationCallback> callback = nullptr;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DistributeOperation_200
 * @tc.desc: Test DistributeOperation when notificationList_ is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("testHashCode");
    operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    sptr<IAnsOperationCallback> callback = nullptr;

    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DistributeOperation_300
 * @tc.desc: Test DistributeOperation when operationInfo's hashcode is not satisfied.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->AddToNotificationList(record);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode("testHashCode");
    operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    sptr<IAnsOperationCallback> callback = nullptr;

    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DistributeOperation_400
 * @tc.desc: Test DistributeOperation ERR_OK.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(true);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode(record->notification->GetKey());
    operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    sptr<IAnsOperationCallback> callback = nullptr;
    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: DistributeOperation_500
 * @tc.desc: Test DistributeOperation when record's NotificationRequestPoint is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    std::shared_ptr<NotificationRecord> record = std::make_shared<NotificationRecord>();
    record->notification = new (std::nothrow) Notification(nullptr);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode(record->notification->GetKey());
    operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    sptr<IAnsOperationCallback> callback = nullptr;
    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: DistributeOperation_600
 * @tc.desc: Test DistributeOperation when record's distributedCollaborate_ is false.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, DistributeOperation_600, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    sptr<NotificationBundleOption> bundle = new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
    sptr<NotificationRequest> request = new (std::nothrow) NotificationRequest();
    request->SetDistributedCollaborate(false);
    auto record = advancedNotificationService_->MakeNotificationRecord(request, bundle);
    advancedNotificationService_->DeleteAll();
    advancedNotificationService_->AddToNotificationList(record);
    sptr<NotificationOperationInfo> operationInfo = new (std::nothrow) NotificationOperationInfo();
    operationInfo->SetHashCode(record->notification->GetKey());
    operationInfo->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    sptr<IAnsOperationCallback> callback = nullptr;
    auto ret = advancedNotificationService_->DistributeOperation(operationInfo, callback);
    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetTargetDeviceStatus_100
 * @tc.desc: Test SetTargetDeviceStatus when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = "testDeviceType";
    uint32_t status = 0;
    const std::string deviceId = "testDeviceId";

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, deviceId);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetTargetDeviceStatus_200
 * @tc.desc: Test SetTargetDeviceStatus when deviceType is empty.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = "";
    uint32_t status = 0;
    uint32_t controlFlag = 0;
    const std::string deviceId = "testDeviceId";
    int32_t userId = 100;

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetTargetDeviceStatus_300
 * @tc.desc: Test SetTargetDeviceStatus when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    uint32_t status = 0;
    uint32_t controlFlag = 0;
    const std::string deviceId = "testDeviceId";
    int32_t userId = 100;

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetTargetDeviceStatus_400
 * @tc.desc: Test SetTargetDeviceStatus when caller has no permission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_400, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(false);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    uint32_t status = 0;
    uint32_t controlFlag = 0;
    const std::string deviceId = "testDeviceId";
    int32_t userId = 100;

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetTargetDeviceStatus_500
 * @tc.desc: Test SetTargetDeviceStatus when deviceType is pad.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_500, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    uint32_t status = 0;
    uint32_t controlFlag = 0;
    const std::string deviceId = "testDeviceId";
    int32_t userId = 100;

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetTargetDeviceStatus_600
 * @tc.desc: Test SetTargetDeviceStatus when deviceType is not pad and pc.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceStatus_600, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    uint32_t status = 0;
    uint32_t controlFlag = 0;
    const std::string deviceId = "testDeviceId";
    int32_t userId = 100;

    auto ret = advancedNotificationService_->SetTargetDeviceStatus(deviceType, status, controlFlag, deviceId, userId);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetTargetDeviceBundleList_100
 * @tc.desc: Test SetTargetDeviceBundleList when caller is not subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceBundleList_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int operatorType = 0;
    const std::vector<std::string> labelList;
    const std::vector<std::string> bundleList;

    auto ret = advancedNotificationService_->SetTargetDeviceBundleList(deviceType, deviceId, operatorType,
        bundleList, labelList);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetTargetDeviceBundleList_200
 * @tc.desc: Test SetTargetDeviceBundleList when caller has no permission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceBundleList_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int operatorType = 0;
    const std::vector<std::string> labelList;
    const std::vector<std::string> bundleList;

    auto ret = advancedNotificationService_->SetTargetDeviceBundleList(deviceType, deviceId, operatorType,
        bundleList, labelList);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetTargetDeviceBundleList_300
 * @tc.desc: Test SetTargetDeviceBundleList when caller has invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceBundleList_300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int operatorType = 0;
    const std::vector<std::string> labelList;
    const std::vector<std::string> bundleList;

    auto ret = advancedNotificationService_->SetTargetDeviceBundleList(deviceType, deviceId, operatorType,
        bundleList, labelList);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetMutilDeviceStatus_100
 * @tc.desc: Test GetMutilDeviceStatus when caller is not subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetMutilDeviceStatus_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    const std::string deviceType = "pad";
    uint32_t flag = 3;
    int32_t userId;
    std::string deviceId = "";

    auto ret = advancedNotificationService_->GetMutilDeviceStatus(deviceType, flag, deviceId, userId);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetTargetDeviceBundleList_100
 * @tc.desc: Test GetTargetDeviceBundleList when caller is not subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetTargetDeviceBundleList_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    const std::string deviceType = "pad";
    const std::string deviceId = "id";
    std::vector<std::string> bundles;
    std::vector<std::string> labels;
    auto ret = advancedNotificationService_->GetTargetDeviceBundleList(deviceType, deviceId, bundles, labels);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetTargetDeviceSwitch_100
 * @tc.desc: Test SetTargetDeviceSwitch when caller is not subsystem.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceSwitch_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_INVALID);
    const std::string deviceType = "";
    const std::string deviceId = "";
    bool notificaitonEnable = false;
    bool liveViewEnable = false;

    auto ret = advancedNotificationService_->SetTargetDeviceSwitch(
        deviceType, deviceId, notificaitonEnable, liveViewEnable);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetTargetDeviceSwitch_200
 * @tc.desc: Test SetTargetDeviceSwitch when caller has no permission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceSwitch_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(false);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    const std::string deviceId = "";
    bool notificaitonEnable = false;
    bool liveViewEnable = false;

    auto ret = advancedNotificationService_->SetTargetDeviceSwitch(
        deviceType, deviceId, notificaitonEnable, liveViewEnable);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetTargetDeviceSwitch_300
 * @tc.desc: Test SetTargetDeviceSwitch when caller has invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetTargetDeviceSwitch_300, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_NATIVE);
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    const std::string deviceId = "";
    bool notificaitonEnable = false;
    bool liveViewEnable = false;

    auto ret = advancedNotificationService_->SetTargetDeviceSwitch(
        deviceType, deviceId, notificaitonEnable, liveViewEnable);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetAllDistribuedEnabledBundles_100
 * @tc.desc: Test GetAllDistribuedEnabledBundles when caller has no permission.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetAllDistribuedEnabledBundles_100, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(false);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    std::vector<NotificationBundleOption> bundleOptions;

    auto ret = advancedNotificationService_->GetAllDistribuedEnabledBundles(deviceType, bundleOptions);

    ASSERT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: GetAllDistribuedEnabledBundles_200
 * @tc.desc: Test GetAllDistribuedEnabledBundles when notificationSvrQueue_ is nullptr.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetAllDistribuedEnabledBundles_200, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    std::vector<NotificationBundleOption> bundleOptions;
    advancedNotificationService_->notificationSvrQueue_ = nullptr;

    auto ret = advancedNotificationService_->GetAllDistribuedEnabledBundles(deviceType, bundleOptions);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetAllDistribuedEnabledBundles_300
 * @tc.desc: Test GetAllDistribuedEnabledBundles when caller has invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetAllDistribuedEnabledBundles_300, Function | SmallTest | Level1)
{
    MockIsVerfyPermisson(true);
    IPCSkeleton::SetCallingTokenID(NATIVE_TOKEN);
    const std::string deviceType = "";
    std::vector<NotificationBundleOption> bundleOptions;

    auto ret = advancedNotificationService_->GetAllDistribuedEnabledBundles(deviceType, bundleOptions);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetDistributedEnabledByBundle_100
 * @tc.desc: Test SetDistributedEnabledByBundle when caller has invalid parameters.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedEnabledByBundle_100, Function | SmallTest | Level1)
{
    const std::string deviceType = "";
    bool enabled = false;
    sptr<NotificationBundleOption> bundleOption = nullptr;

    auto ret = advancedNotificationService_->SetDistributedEnabledByBundle(bundleOption, deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetDistributedEnabled_100
 * @tc.desc: Test SetDistributedEnabled when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedEnabled_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    bool enabled = 0;

    auto ret = advancedNotificationService_->SetDistributedEnabled(deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetDistributedEnabled_200
 * @tc.desc: Test SetDistributedEnabled when succeed to call.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedEnabled_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    bool enabled = 0;

    auto ret = advancedNotificationService_->SetDistributedEnabled(deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsDistributedEnabled_100
 * @tc.desc: Test IsDistributedEnabled when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, IsDistributedEnabled_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    bool enabled = 0;

    auto ret = advancedNotificationService_->IsDistributedEnabled(deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: IsDistributedEnabled_200
 * @tc.desc: Test IsDistributedEnabled when succeed to call.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, IsDistributedEnabled_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    const std::string deviceType = NotificationConstant::PAD_DEVICE_TYPE;
    bool enabled = 0;

    auto ret = advancedNotificationService_->IsDistributedEnabled(deviceType, enabled);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetDistributedAbility_100
 * @tc.desc: Test GetDistributedAbility when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetDistributedAbility_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    int32_t abilityId = 0;

    auto ret = advancedNotificationService_->GetDistributedAbility(abilityId);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetDistributedAuthStatus_100
 * @tc.desc: Test GetDistributedAuthStatus when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetDistributedAuthStatus_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int32_t userId = 100;
    bool isAuth = false;

    auto ret = advancedNotificationService_->GetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetDistributedAuthStatus_200
 * @tc.desc: Test GetDistributedAuthStatus when succeed to call.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetDistributedAuthStatus_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int32_t userId = 100;
    bool isAuth = false;

    auto ret = advancedNotificationService_->GetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetDistributedAuthStatus_100
 * @tc.desc: Test SetDistributedAuthStatus when caller is not subsystem or system app.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedAuthStatus_100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int32_t userId = 100;
    bool isAuth = false;

    auto ret = advancedNotificationService_->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);

    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: SetDistributedAuthStatus_200
 * @tc.desc: Test SetDistributedAuthStatus when succeed to call.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, SetDistributedAuthStatus_200, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(true);
    const std::string deviceType = "";
    const std::string deviceId = "";
    int32_t userId = 100;
    bool isAuth = false;

    auto ret = advancedNotificationService_->SetDistributedAuthStatus(deviceType, deviceId, userId, isAuth);

    ASSERT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetDistributedDevicelist_0100
 * @tc.desc: Test GetDistributedDevicelist.
 * @tc.type: FUNC
 */
HWTEST_F(AdvancedNotificationDistMgrServiceTest, GetDistributedDevicelist_0100, Function | SmallTest | Level1)
{
    MockGetTokenTypeFlag(ATokenTypeEnum::TOKEN_HAP);
    MockIsSystemApp(false);
    std::vector<std::string> deviceTypes;
    auto ret = advancedNotificationService_->GetDistributedDevicelist(deviceTypes);
    ASSERT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}
}  // namespace Notification
}  // namespace OHOS
