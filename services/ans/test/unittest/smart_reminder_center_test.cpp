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

#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
#include "gtest/gtest.h"
#define private public
#define protected public
#include "notification_preferences.h"
#include "smart_reminder_center.h"
#include "distributed_device_data_service.h"
#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#include "notification_subscriber_manager.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {

class SmartReminderCenterTest : public testing::Test {
public:
    SmartReminderCenterTest()
    {}
    ~SmartReminderCenterTest()
    {}
    static void SetUpTestCas(void) {};
    static void TearDownTestCase(void) {};
    void SetUp();
    void TearDown() {};
public:
    std::shared_ptr<SmartReminderCenter> smartReminderCenter_;
};

void SmartReminderCenterTest::SetUp(void)
{
    smartReminderCenter_ = DelayedSingleton<SmartReminderCenter>::GetInstance();
}

/**
 * @tc.name: Test IsNeedSynergy
 * @tc.desc: Test IsNeedSynergy
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsNeedSynergy_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    string deviceType = "test";
    string ownerBundleName = "testName";
    int32_t ownerUid = 100;

    auto res = smartReminderCenter_->IsNeedSynergy(slotType, deviceType, ownerBundleName, ownerUid);
    ASSERT_FALSE(res);

    auto err = NotificationPreferences::GetInstance()->SetSmartReminderEnabled(deviceType, true);
    ASSERT_EQ(err, ERR_OK);
    res = smartReminderCenter_->IsNeedSynergy(slotType, deviceType, ownerBundleName, ownerUid);
    ASSERT_FALSE(res);

    err = NotificationPreferences::GetInstance()->SetSmartReminderEnabled(deviceType, true);
    ASSERT_EQ(err, ERR_OK);
    res = smartReminderCenter_->IsNeedSynergy(slotType, deviceType, ownerBundleName, ownerUid);
    ASSERT_FALSE(res);

    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption(ownerBundleName, ownerUid));
    err = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    ASSERT_EQ(err, ERR_OK);
    res = smartReminderCenter_->IsNeedSynergy(slotType, deviceType, ownerBundleName, ownerUid);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: Test HandleAffectedReminder
 * @tc.desc: Test HandleAffectedReminder
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleAffectedReminder_00001, Function | SmallTest | Level1)
{
    string deviceType = "test";
    shared_ptr<ReminderAffected> reminderAffected = make_shared<ReminderAffected>();
    std::vector<std::pair<std::string, std::string>> affectedBy;
    auto affectedByOne = std::make_pair("test", "0000");
    affectedBy.push_back(affectedByOne);
    reminderAffected->affectedBy_ = affectedBy;
    reminderAffected->reminderFlags_ = make_shared<NotificationFlags>();

    set<string> validDevices;
    validDevices.insert("test");

    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();
    
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    statusMap.insert(pair<string,
        bitset<DistributedDeviceStatus::STATUS_SIZE>>("test", bitset<DistributedDeviceStatus::STATUS_SIZE>(0)));

    auto res = smartReminderCenter_->HandleAffectedReminder(
        deviceType, reminderAffected, validDevices,
        statusMap,  notificationFlagsOfDevices);
    ASSERT_TRUE(res);

    auto affectedByTwo = std::make_pair("test111", "1111");
    affectedBy.push_back(affectedByTwo);
    reminderAffected->affectedBy_ = affectedBy;
    res = smartReminderCenter_->HandleAffectedReminder(
        deviceType, reminderAffected, validDevices,
        statusMap,  notificationFlagsOfDevices);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: Test IsCollaborationAllowed
 * @tc.desc: Test IsCollaborationAllowed
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsCollaborationAllowed_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto res = smartReminderCenter_->IsCollaborationAllowed(request);
    ASSERT_TRUE(res);

    request->SetIsSystemApp(true);
    request->SetNotDistributed(true);
    res = smartReminderCenter_->IsCollaborationAllowed(request);
    ASSERT_FALSE(res);

    request->SetNotDistributed(false);
    request->SetForceDistributed(true);
    res = smartReminderCenter_->IsCollaborationAllowed(request);
    ASSERT_TRUE(res);

    request->SetForceDistributed(false);
    res = smartReminderCenter_->IsCollaborationAllowed(request);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: Test ReminderDecisionProcess
 * @tc.desc: Test ReminderDecisionProcess
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, ReminderDecisionProcess_00001, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetIsSystemApp(true);
    request->SetNotDistributed(true);
    auto deviceFlags = request->GetDeviceFlags();
    ASSERT_EQ(deviceFlags, nullptr);
    
    smartReminderCenter_->ReminderDecisionProcess(request);
    deviceFlags = request->GetDeviceFlags();
    ASSERT_NE(deviceFlags, nullptr);
}

/**
 * @tc.name: Test ReminderDecisionProcess
 * @tc.desc: Test ReminderDecisionProcess
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, InitValidDevices_00001, Function | SmallTest | Level1)
{
    // need subscriber
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);

    set<string> validDevices;
    set<string> smartDevices;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    NotificationConstant::SWITCH_STATE enableStatus = NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON;
    NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(
        request->GetSlotType(), "headset", enableStatus);
    smartReminderCenter_->InitValidDevices(validDevices, smartDevices, statusMap, request);
    ASSERT_EQ(request->GetNotificationControlFlags(), 0);
}

/**
 * @tc.name: Test ReminderDecisionProcess
 * @tc.desc: Test ReminderDecisionProcess
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, InitValidDevices_00002, Function | SmallTest | Level1)
{
    // need subscriber
    std::string ownerBundleName = "test";
    int32_t ownerUid = 100;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetOwnerBundleName(ownerBundleName);
    request->SetOwnerUid(ownerUid);

    std::string deviceType = "headset";
    auto res = NotificationPreferences::GetInstance()->SetSmartReminderEnabled(deviceType, true);
    ASSERT_EQ(res, 0);

    sptr<NotificationBundleOption> bundleOption(
        new (std::nothrow) NotificationBundleOption(ownerBundleName, ownerUid));
    res = NotificationPreferences::GetInstance()->SetDistributedEnabledByBundle(
        bundleOption, deviceType, true);
    ASSERT_EQ(res, 0);

    set<string> validDevices;
    set<string> smartDevices;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    smartReminderCenter_->InitValidDevices(validDevices, smartDevices, statusMap, request);
    ASSERT_EQ(request->GetNotificationControlFlags(), 0);
}

HWTEST_F(SmartReminderCenterTest, InitValidDevices_00003, Function | SmallTest | Level1)
{
    // need subscriber
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    auto record = std::make_shared<NotificationSubscriberManager::SubscriberRecord>();
    record->subscribedAll = true;
    record->deviceType = NotificationConstant::THIRD_PARTY_WEARABLE_DEVICE_TYPE;
    NotificationSubscriberManager::GetInstance()->subscriberRecordList_.push_back(record);

    set<string> validDevices;
    set<string> smartDevices;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    smartReminderCenter_->InitValidDevices(validDevices, smartDevices, statusMap, request);
    EXPECT_EQ(validDevices.size(), 1);
}

#ifdef ALL_SCENARIO_COLLABORATION
/**
 * @tc.name: InitPcPadDevices_100
 * @tc.desc: Test InitPcPadDevices
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, InitPcPadDevices_100, Function | SmallTest | Level1)
{
    std::string deviceType = NotificationConstant::PC_DEVICE_TYPE;
    set<string> validDevices;
    set<string> smartDevices;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;

    smartReminderCenter_->InitPcPadDevices(deviceType, validDevices, smartDevices, statusMap, request);

    ASSERT_EQ(validDevices.size(), 0);
    ASSERT_EQ(smartDevices.size(), 0);
}

/**
 * @tc.name: InitPcPadDevices_200
 * @tc.desc: Test InitPcPadDevices when CURRENT DEVICE with live view slot type
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, InitPcPadDevices_200, Function | SmallTest | Level1)
{
    std::string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    set<string> validDevices;
    set<string> smartDevices;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;

    smartReminderCenter_->InitPcPadDevices(deviceType, validDevices, smartDevices, statusMap, request);

    ASSERT_EQ(validDevices.size(), 0);
    ASSERT_EQ(smartDevices.size(), 0);
}

/**
 * @tc.name: InitPcPadDevices_300
 * @tc.desc: Test InitPcPadDevices when ANS_VOIP
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, InitPcPadDevices_300, Function | SmallTest | Level1)
{
    std::string deviceType = NotificationConstant::PC_DEVICE_TYPE;
    set<string> validDevices;
    set<string> smartDevices;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetClassification(NotificationConstant::ANS_VOIP);
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    smartReminderCenter_->InitPcPadDevices(deviceType, validDevices, smartDevices, statusMap, request);

    ASSERT_EQ(validDevices.size(), 0);
    ASSERT_EQ(smartDevices.size(), 0);
}
#endif

/**
 * @tc.name: FillRequestExtendInfo_100
 * @tc.desc: Test FillRequestExtendInfo
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, FillRequestExtendInfo_100, Function | SmallTest | Level1)
{
    std::string deviceType = "testType";
    std::string deviceId = "testId";
    DeviceStatus deviceStatus(deviceType, deviceId);
    sptr<NotificationRequest> request(new NotificationRequest(1));
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.name = "testName";
    appInfo.appIndex = 0;
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    bundleResourceInfo.label = "label";

    smartReminderCenter_->FillRequestExtendInfo(deviceType, deviceStatus, request, appInfo, bundleResourceInfo);

    ASSERT_NE(request->GetExtendInfo(), nullptr);
}

/**
 * @tc.name: HandleReminderMethods_100
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_100, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetClassification("ANS_VOIP");
    set<string> syncDevices;
    set<string> smartDevices;
    shared_ptr<NotificationFlags> defaultFlag = nullptr;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_EQ(syncDevices.find(deviceType), syncDevices.end());
}

/**
 * @tc.name: HandleReminderMethods_200
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_200, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    auto defaultFlag = std::make_shared<NotificationFlags>();
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_EQ(smartDevices.find(deviceType), smartDevices.end());
}

/**
 * @tc.name: HandleReminderMethods_300
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_300, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_NE(notificationFlagsOfDevices->find(deviceType), notificationFlagsOfDevices->end());
}

/**
 * @tc.name: HandleReminderMethods_400
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_400, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_EQ(statusMap.find(deviceType), statusMap.end());
}

/**
 * @tc.name: HandleReminderMethods_500
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_500, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    smartDevices.insert("headset");
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_EQ(statusMap.find(deviceType), statusMap.end());
}

/**
 * @tc.name: HandleReminderMethods_600
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_600, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    vector<shared_ptr<ReminderAffected>> reminderAffecteds = { nullptr };
    std::string key = "5";
    reminderFilterDevice[key] = reminderAffecteds;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    smartDevices.insert("headset");
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap{};
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    ASSERT_EQ(statusMap.find(deviceType), statusMap.end());
}

/**
 * @tc.name: HandleReminderMethods_700
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_700, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    auto reminderAffected = std::make_shared<ReminderAffected>();
    reminderAffected->status_ = "1111";
    vector<shared_ptr<ReminderAffected>> reminderAffecteds = { reminderAffected };
    std::string key = "5";
    reminderFilterDevice[key] = reminderAffecteds;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    smartDevices.insert("headset");
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap = {};
    statusMap.insert(pair<string,
        bitset<DistributedDeviceStatus::STATUS_SIZE>>("1111", bitset<DistributedDeviceStatus::STATUS_SIZE>(0)));
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    auto bitStatus = bitset<DistributedDeviceStatus::STATUS_SIZE>(0);
    ASSERT_FALSE(smartReminderCenter_->CompareStatus(reminderAffected->status_, bitStatus));
}

/**
 * @tc.name: HandleReminderMethods_800
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_800, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    auto reminderAffected = std::make_shared<ReminderAffected>();
    reminderAffected->status_ = "0000";
    vector<shared_ptr<ReminderAffected>> reminderAffecteds = { reminderAffected };
    std::string key = "5";
    reminderFilterDevice[key] = reminderAffecteds;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    smartDevices.insert("headset");
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap = {};
    statusMap.insert(pair<string,
        bitset<DistributedDeviceStatus::STATUS_SIZE>>("1111", bitset<DistributedDeviceStatus::STATUS_SIZE>(0)));
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    auto bitStatus = bitset<DistributedDeviceStatus::STATUS_SIZE>(0);
    ASSERT_TRUE(smartReminderCenter_->CompareStatus(reminderAffected->status_, bitStatus));
    ASSERT_EQ(reminderAffected->affectedBy_.size(), 0);
}

/**
 * @tc.name: HandleReminderMethods_900
 * @tc.desc: Test HandleReminderMethods
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, HandleReminderMethods_900, Function | SmallTest | Level1)
{
    string deviceType = NotificationConstant::CURRENT_DEVICE_TYPE;
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    auto reminderAffected = std::make_shared<ReminderAffected>();
    reminderAffected->status_ = "0000";
    reminderAffected->affectedBy_ = { std::make_pair("test111", "0000") };
    vector<shared_ptr<ReminderAffected>> reminderAffecteds = { reminderAffected };
    std::string key = "5";
    reminderFilterDevice[key] = reminderAffecteds;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    set<string> syncDevices;
    syncDevices.insert(deviceType);
    set<string> smartDevices;
    smartDevices.insert(deviceType);
    smartDevices.insert("headset");
    shared_ptr<NotificationFlags> defaultFlag = make_shared<NotificationFlags>();;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap = {};
    statusMap.insert(pair<string,
        bitset<DistributedDeviceStatus::STATUS_SIZE>>("1111", bitset<DistributedDeviceStatus::STATUS_SIZE>(0)));
    shared_ptr<map<string, shared_ptr<NotificationFlags>>> notificationFlagsOfDevices =
        make_shared<map<string, shared_ptr<NotificationFlags>>>();

    smartReminderCenter_->HandleReminderMethods(deviceType, reminderFilterDevice, request, syncDevices,
        smartDevices, defaultFlag, statusMap, notificationFlagsOfDevices);

    auto bitStatus = bitset<DistributedDeviceStatus::STATUS_SIZE>(0);
    ASSERT_TRUE(smartReminderCenter_->CompareStatus(reminderAffected->status_, bitStatus));
    ASSERT_NE(reminderAffected->affectedBy_.size(), 0);
}

/**
 * @tc.name: GetAppSwitch_100
 * @tc.desc: Test GetAppSwitch
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetAppSwitch_100, Function | SmallTest | Level1)
{
    const string deviceType = NotificationConstant::WEARABLE_DEVICE_TYPE;
    const string ownerBundleName = "testBundle";
    int32_t ownerUid = 0;

    auto ret = smartReminderCenter_->GetAppSwitch(deviceType, ownerBundleName, ownerUid);

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetSmartSwitch_100
 * @tc.desc: Test GetSmartSwitch
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetSmartSwitch_100, Function | SmallTest | Level1)
{
    const string deviceType = NotificationConstant::WEARABLE_DEVICE_TYPE;

    auto ret = smartReminderCenter_->GetSmartSwitch(deviceType);

    ASSERT_FALSE(ret);
}

/**
 * @tc.name: GetReminderAffecteds_100
 * @tc.desc: Test GetReminderAffecteds
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetReminderAffecteds_100, Function | SmallTest | Level1)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;

    smartReminderCenter_->GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);

    std::string key = "5#7#0";
    ASSERT_EQ(reminderFilterDevice.find(key), reminderFilterDevice.end());
}

/**
 * @tc.name: GetReminderAffecteds_200
 * @tc.desc: Test GetReminderAffecteds
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetReminderAffecteds_200, Function | SmallTest | Level1)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;

    smartReminderCenter_->GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);

    std::string key = "5#7#0";
    ASSERT_EQ(reminderFilterDevice.find(key), reminderFilterDevice.end());
}

/**
 * @tc.name: GetReminderAffecteds_300
 * @tc.desc: Test GetReminderAffecteds
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetReminderAffecteds_300, Function | SmallTest | Level1)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;
    std::string key = "5#7#0";
    reminderFilterDevice[key] = reminderAffecteds;

    smartReminderCenter_->GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);

    std::string key1 = "5#7";
    ASSERT_EQ(reminderFilterDevice.find(key1), reminderFilterDevice.end());
}

/**
 * @tc.name: GetReminderAffecteds_400
 * @tc.desc: Test GetReminderAffecteds
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetReminderAffecteds_400, Function | SmallTest | Level1)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;
    std::string key = "5#7";
    reminderFilterDevice[key] = reminderAffecteds;

    smartReminderCenter_->GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);

    std::string key1 = "5";
    ASSERT_EQ(reminderFilterDevice.find(key1), reminderFilterDevice.end());
}

/**
 * @tc.name: GetReminderAffecteds_500
 * @tc.desc: Test GetReminderAffecteds
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, GetReminderAffecteds_500, Function | SmallTest | Level1)
{
    map<string, vector<shared_ptr<ReminderAffected>>> reminderFilterDevice{};
    sptr<NotificationRequest> request(new NotificationRequest(1));
    auto localLiveViewContent = std::make_shared<NotificationLocalLiveViewContent>();
    auto content = std::make_shared<NotificationContent>(localLiveViewContent);
    request->SetContent(content);
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    vector<shared_ptr<ReminderAffected>> reminderAffecteds;
    vector<shared_ptr<ReminderAffected>> reminderAffecteds1 = { nullptr };
    std::string key = "5";
    reminderFilterDevice[key] = reminderAffecteds1;

    smartReminderCenter_->GetReminderAffecteds(reminderFilterDevice, request, reminderAffecteds);

    ASSERT_EQ(reminderAffecteds.size(), 1);
}

#ifdef NOTIFICATION_EXTENSION_SUBSCRIPTION_SUPPORTED
HWTEST_F(SmartReminderCenterTest, InitThirdPartyWearableDevices_00001, Function | SmallTest | Level1)
{
    std::string ownerBundleName = "test";
    int32_t ownerUid = 100;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUid(1000);
    request->SetOwnerBundleName(ownerBundleName);
    request->SetOwnerUid(ownerUid);

    set<string> validDevices;
    smartReminderCenter_->InitThirdPartyWearableDevices(validDevices, request);
    EXPECT_EQ(validDevices.size(), 1);
}

HWTEST_F(SmartReminderCenterTest, InitThirdPartyWearableDevices_00002, Function | SmallTest | Level1)
{
    std::string ownerBundleName = "test";
    int32_t ownerUid = 100;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetCreatorUid(1000);
    request->SetOwnerBundleName(ownerBundleName);
    request->SetOwnerUid(ownerUid);

    set<string> validDevices;
    smartReminderCenter_->InitThirdPartyWearableDevices(validDevices, request);
    EXPECT_EQ(validDevices.size(), 0);
}

HWTEST_F(SmartReminderCenterTest, InitThirdPartyWearableDevices_00003, Function | SmallTest | Level1)
{
    std::string ownerBundleName = "test";
    int32_t ownerUid = 100;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUid(NON_BUNDLE_NAME_UID);
    request->SetOwnerBundleName(ownerBundleName);
    request->SetOwnerUid(ownerUid);

    set<string> validDevices;
    smartReminderCenter_->InitThirdPartyWearableDevices(validDevices, request);
    EXPECT_EQ(validDevices.size(), 0);
}

HWTEST_F(SmartReminderCenterTest, InitThirdPartyWearableDevices_00004, Function | SmallTest | Level1)
{
    std::string ownerBundleName = "test";
    int32_t ownerUid = 100;
    sptr<NotificationRequest> request(new NotificationRequest(1));
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    request->SetCreatorUid(1000);
    request->SetOwnerBundleName(ownerBundleName);
    request->SetOwnerUid(ownerUid);
    request->SetClassification(NotificationConstant::ANS_VOIP);

    set<string> validDevices;
    smartReminderCenter_->InitThirdPartyWearableDevices(validDevices, request);
    EXPECT_EQ(validDevices.size(), 0);
}
#endif

/**
 * @tc.name: IsSmartRemindBySwitch_100
 * @tc.desc: Test IsSmartRemindBySwitch when liveView switch closed
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsSmartRemindBySwitch_100, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType1";
    std::string deviceId = "123";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    DeviceStatus deviceStatus(deviceType, deviceId);
    bool result = smartReminderCenter_->IsSmartRemindBySwitch(deviceType, deviceStatus, request);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsSmartRemindBySwitch_200
 * @tc.desc: Test IsSmartRemindBySwitch when liveView switch open and slot switch close
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsSmartRemindBySwitch_200, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType2";
    std::string deviceId = "123";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    DeviceStatus deviceStatus(deviceType, deviceId);
    DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(deviceType, deviceId, false, true);
    bool result = smartReminderCenter_->IsSmartRemindBySwitch(deviceType, deviceStatus, request);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsSmartRemindBySwitch_300
 * @tc.desc: Test IsSmartRemindBySwitch when notification switch closed
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsSmartRemindBySwitch_300, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType3";
    std::string deviceId = "123";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    DeviceStatus deviceStatus(deviceType, deviceId);
    bool result = smartReminderCenter_->IsSmartRemindBySwitch(deviceType, deviceStatus, request);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsSmartRemindBySwitch_400
 * @tc.desc: Test IsSmartRemindBySwitch when notification switch open and slot switch close
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsSmartRemindBySwitch_400, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType4";
    std::string deviceId = "123";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    DeviceStatus deviceStatus(deviceType, deviceId);
    DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(deviceType, deviceId, true, false);
    bool result = smartReminderCenter_->IsSmartRemindBySwitch(deviceType, deviceStatus, request);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: IsSmartRemindBySwitch_500
 * @tc.desc: Test IsSmartRemindBySwitch when notification switch open and slot switch open
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, IsSmartRemindBySwitch_500, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType5";
    std::string deviceId = "123";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    DeviceStatus deviceStatus(deviceType, deviceId);
    DistributedDeviceDataService::GetInstance().SetDeviceSyncSwitch(deviceType, deviceId, true, false);
    NotificationPreferences::GetInstance()->SetDistributedEnabled(
        NotificationConstant::CURRENT_DEVICE_TYPE,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_ON);
    bool result = smartReminderCenter_->IsSmartRemindBySwitch(deviceType, deviceStatus, request);
    ASSERT_EQ(result, true);
    NotificationPreferences::GetInstance()->SetDistributedEnabled(
        NotificationConstant::CURRENT_DEVICE_TYPE,
        NotificationConstant::SWITCH_STATE::USER_MODIFIED_OFF);
}

/**
 * @tc.name: CheckHealthWhiteList_100
 * @tc.desc: Test CheckHealthWhiteList when not liveView
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckHealthWhiteList_100, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    bool result = smartReminderCenter_->CheckHealthWhiteList(request, deviceType);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckHealthWhiteList_200
 * @tc.desc: Test CheckHealthWhiteList when deviceType not watch
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckHealthWhiteList_200, Function | SmallTest | Level1)
{
    std::string deviceType = "testDeviceType";
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    bool result = smartReminderCenter_->CheckHealthWhiteList(request, deviceType);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckHealthWhiteList_300
 * @tc.desc: Test CheckHealthWhiteList when whiteList is null
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckHealthWhiteList_300, Function | SmallTest | Level1)
{
    std::string deviceType = NotificationConstant::WEARABLE_DEVICE_TYPE;;
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request->SetOwnerBundleName("testBundleName1");
    bool result = smartReminderCenter_->CheckHealthWhiteList(request, deviceType);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckScreenOffForCollaboration_100
 * @tc.desc: Test sync devices without PC/PAD
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckScreenOffForCollaboration_100, Function | SmallTest | Level1)
{
    set<string> syncDevices;
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    statusMap[NotificationConstant::CURRENT_DEVICE_TYPE].set(DistributedDeviceStatus::LOCK_FLAG, true);
    smartReminderCenter_->CheckScreenOffForCollaboration(syncDevices, statusMap);
    EXPECT_TRUE(statusMap[NotificationConstant::CURRENT_DEVICE_TYPE].test(DistributedDeviceStatus::LOCK_FLAG));
}

/**
 * @tc.name: CheckScreenOffForCollaboration_200
 * @tc.desc: Test status map without current
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckScreenOffForCollaboration_200, Function | SmallTest | Level1)
{
    set<string> syncDevices = {NotificationConstant::PAD_DEVICE_TYPE};
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    smartReminderCenter_->CheckScreenOffForCollaboration(syncDevices, statusMap);
    EXPECT_FALSE(statusMap.count(NotificationConstant::CURRENT_DEVICE_TYPE));
}

/**
 * @tc.name: CheckScreenOffForCollaboration_300
 * @tc.desc: Test not modify current screen lock
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckScreenOffForCollaboration_300, Function | SmallTest | Level1)
{
    set<string> syncDevices = {NotificationConstant::PAD_DEVICE_TYPE};
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    statusMap[NotificationConstant::CURRENT_DEVICE_TYPE].set(DistributedDeviceStatus::LOCK_FLAG, false);
    smartReminderCenter_->CheckScreenOffForCollaboration(syncDevices, statusMap);
    EXPECT_FALSE(statusMap[NotificationConstant::CURRENT_DEVICE_TYPE].test(DistributedDeviceStatus::LOCK_FLAG));
}

/**
 * @tc.name: CheckScreenOffForCollaboration_400
 * @tc.desc: Test status map without current
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, CheckScreenOffForCollaboration_400, Function | SmallTest | Level1)
{
    set<string> syncDevices = {NotificationConstant::PAD_DEVICE_TYPE};
    map<string, bitset<DistributedDeviceStatus::STATUS_SIZE>> statusMap;
    statusMap[NotificationConstant::CURRENT_DEVICE_TYPE].set(DistributedDeviceStatus::LOCK_FLAG, true);
    smartReminderCenter_->CheckScreenOffForCollaboration(syncDevices, statusMap);
    EXPECT_TRUE(statusMap.count(NotificationConstant::CURRENT_DEVICE_TYPE));
}

/**
 * @tc.name: SetSyncDevice_100
 * @tc.desc: Test status map without current
 * @tc.type: FUNC
 */
HWTEST_F(SmartReminderCenterTest, SetSyncDevice_100, Function | SmallTest | Level1)
{
    SmartReminderCenter center;
    sptr<NotificationRequest> request = new NotificationRequest(100);
    std::set<std::string> syncDevices = {"headset", "wearable"};

    smartReminderCenter_->SetSyncDevice(request, syncDevices);

    auto extendInfo = request->GetExtendInfo();
    ASSERT_NE(extendInfo, nullptr);

    auto deviceList = extendInfo->GetIntParam("collaboration_device_list", -1);
    ASSERT_EQ(deviceList, 5); // 5 = 1 << 0 | 1 << 2
}
}   //namespace Notification
}   //namespace OHOS
#endif
