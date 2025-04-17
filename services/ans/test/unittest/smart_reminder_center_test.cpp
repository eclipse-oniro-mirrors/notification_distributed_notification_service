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
#include "ans_inner_errors.h"
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

    auto res = smartReminderCenter_->HandleAffectedReminder(
        deviceType, reminderAffected, validDevices, notificationFlagsOfDevices);
    ASSERT_TRUE(res);

    auto affectedByTwo = std::make_pair("test111", "1111");
    affectedBy.push_back(affectedByTwo);
    reminderAffected->affectedBy_ = affectedBy;
    res = smartReminderCenter_->HandleAffectedReminder(
        deviceType, reminderAffected, validDevices, notificationFlagsOfDevices);
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
    NotificationPreferences::GetInstance()->SetDistributedEnabledBySlot(
                request->GetSlotType(), "headset", true);
    smartReminderCenter_->InitValidDevices(validDevices, request);
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
    smartReminderCenter_->InitValidDevices(validDevices, request);
    ASSERT_EQ(request->GetNotificationControlFlags(), 0);
}
}   //namespace Notification
}   //namespace OHOS
#endif