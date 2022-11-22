/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "ans_inner_errors.h"
#include "ans_ut_constant.h"
#define private public
#define protected public
#include "notification_preferences.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationPreferencesTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown();

    void TestAddNotificationSlot();
    void TestAddNotificationSlot(NotificationPreferencesInfo &info);

    static sptr<NotificationBundleOption> bundleOption_;
    static sptr<NotificationBundleOption> noExsitbundleOption_;
    static sptr<NotificationBundleOption> bundleEmptyOption_;
};

sptr<NotificationBundleOption> NotificationPreferencesTest::bundleOption_ =
    new NotificationBundleOption(TEST_DEFUALT_BUNDLE, NON_SYSTEM_APP_UID);
sptr<NotificationBundleOption> NotificationPreferencesTest::noExsitbundleOption_ =
    new NotificationBundleOption(std::string("notExsitBundleName"), NON_SYSTEM_APP_UID);
sptr<NotificationBundleOption> NotificationPreferencesTest::bundleEmptyOption_ =
    new NotificationBundleOption(std::string(), NON_SYSTEM_APP_UID);

void NotificationPreferencesTest::TearDown()
{
    NotificationPreferences::GetInstance().ClearNotificationInRestoreFactorySettings();
}

void NotificationPreferencesTest::TestAddNotificationSlot()
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots);
}

void NotificationPreferencesTest::TestAddNotificationSlot(NotificationPreferencesInfo &info)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    NotificationPreferences::GetInstance().CheckSlotForCreateSlot(bundleOption_, slot, info);
}

/**
 * @tc.number    : AddNotificationSlots_00100
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB , return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : AddNotificationSlots_00200
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when bundleName is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleEmptyOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationSlots_00300
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slots is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationSlots_00400
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slot is nullptr in vector, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = nullptr;
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
}

/**
 * @tc.number    : AddNotificationSlots_00500
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB when slots is same, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::SOCIAL_COMMUNICATION);

    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot1);
    slots.push_back(slot2);

    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : AddNotificationSlots_00600
 * @tc.name      :
 * @tc.desc      : Add a notification slot into distrube DB , return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationSlots_00600, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(nullptr, slots),
        (int)ERR_ANS_INVALID_PARAM);
}



/**
 * @tc.number    : RemoveNotificationSlot_00100
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB , return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_OK);
}

/**
 * @tc.number    : RemoveNotificationSlot_00200
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when bundle name is null, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationSlot(
                  bundleEmptyOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationSlot_00300
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00300, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationSlot(
                  noExsitbundleOption_, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationSlot_00400
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00400, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::SERVICE_REMINDER),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationSlot_00500
 * @tc.name      :
 * @tc.desc      : Remove a notification slot from disturbe DB , return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationSlot_00500, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationSlot(
                  nullptr, NotificationConstant::SlotType::OTHER),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00100
 * @tc.name      :
 * @tc.desc      : Remove notification for bundle from disturbe DB, return is ERR_OK;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationForBundle(bundleOption_), (int)ERR_OK);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00200
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationForBundle(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00300
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00300, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationForBundle(noExsitbundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationForBundle_00400
 * @tc.name      :
 * @tc.desc      :  Remove notification for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM;
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationForBundle_00400, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationForBundle(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00100
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots), (int)ERR_OK);
    std::string des("This is a description.");
    slot->SetDescription(des);
    slots.clear();
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(bundleOption_, slots), (int)ERR_OK);
}

/**
 * @tc.number    : UpdateNotificationSlots_00200
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundleName is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(bundleEmptyOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00300
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when slots is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(bundleOption_, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : UpdateNotificationSlots_00400
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundle does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00400, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(noExsitbundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : UpdateNotificationSlots_00500
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(noExsitbundleOption_, slots),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : UpdateNotificationSlots_00600
 * @tc.name      :
 * @tc.desc      : Update notification slot into disturbe DB when bundleName is null, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, UpdateNotificationSlots_00600, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().UpdateNotificationSlots(nullptr, slots),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlot_00100
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_OK);
}

/**
 * @tc.number    : GetNotificationSlot_00200
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlot(
                  bundleEmptyOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlot_00300
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when slot type does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00300, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlot(
                  bundleOption_, NotificationConstant::SlotType::CONTENT_INFORMATION, slot),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlot_00400
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00400, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    sptr<NotificationSlot> slot;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlot(
                  noExsitbundleOption_, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlot_00500
 * @tc.name      :
 * @tc.desc      : Update notification slot group into disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlot_00500, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlot(
                  nullptr, NotificationConstant::SlotType::OTHER, slot),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationAllSlots_00100
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB after add a notification slot, return is ERR_OK, get all
 * notifications size is 1.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00100, Function | SmallTest | Level1)
{
    TestAddNotificationSlot();
    std::vector<sptr<NotificationSlot>> slotsResult;
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().GetNotificationAllSlots(bundleOption_, slotsResult), (int)ERR_OK);
    EXPECT_EQ((int)slotsResult.size(), 1);
}

/**
 * @tc.number    : GetNotificationAllSlots_00200
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB after add some notification slot, return is ERR_OK, get
 * all notifications size is the same of adding notifications size.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00200, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot1 = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    sptr<NotificationSlot> slot2 = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    std::vector<sptr<NotificationSlot>> slots;
    slots.push_back(slot1);
    slots.push_back(slot2);
    NotificationPreferences::GetInstance().AddNotificationSlots(bundleOption_, slots);

    std::vector<sptr<NotificationSlot>> slotsResult;
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().GetNotificationAllSlots(bundleOption_, slotsResult), (int)ERR_OK);
    EXPECT_EQ((int)slotsResult.size(), 2);
}

/**
 * @tc.number    : GetNotificationAllSlots_00300
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00300, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationAllSlots(bundleEmptyOption_, slotsResult),
        (int)ERR_ANS_INVALID_PARAM);
    EXPECT_EQ((int)slotsResult.size(), 0);
}

/**
 * @tc.number    : GetNotificationAllSlots_00400
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundle name does not exsit, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00400, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationAllSlots(noExsitbundleOption_, slotsResult),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
    EXPECT_EQ((int)slotsResult.size(), 0);
}

/**
 * @tc.number    : GetNotificationAllSlots_00500
 * @tc.name      :
 * @tc.desc      : Get all notification slots from disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationAllSlots_00500, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slotsResult;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationAllSlots(nullptr, slotsResult),
        (int)ERR_ANS_INVALID_PARAM);
    EXPECT_EQ((int)slotsResult.size(), 0);
}

/**
 * @tc.number    : SetShowBadge_00100
 * @tc.name      :
 * @tc.desc      : Set bundle show badge into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetShowBadge_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetShowBadge(bundleOption_, true), (int)ERR_OK);
}

/**
 * @tc.number    : SetShowBadge_00200
 * @tc.name      :
 * @tc.desc      : Set bundle show badge into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetShowBadge_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().SetShowBadge(bundleEmptyOption_, true), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : IsShowBadge_00100
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB , return is ERR_OK and show badge is true.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00100, Function | SmallTest | Level1)
{
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetShowBadge(bundleOption_, true), (int)ERR_OK);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().IsShowBadge(bundleOption_, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);
}

/**
 * @tc.number    : IsShowBadge_00200
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB when bundle name is null, return is ERR_OK and show badge is
 * true.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00200, Function | SmallTest | Level1)
{
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().IsShowBadge(bundleEmptyOption_, enable),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : IsShowBadge_00300
 * @tc.name      :
 * @tc.desc      : Get bunlde show badge from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, IsShowBadge_00300, Function | SmallTest | Level1)
{
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().IsShowBadge(nullptr, enable),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetImportance_00100
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00100, Function | SmallTest | Level1)
{
    int importance = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetImportance(bundleOption_, importance), (int)ERR_OK);
}

/**
 * @tc.number    : SetImportance_00200
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00200, Function | SmallTest | Level1)
{
    int importance = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetImportance(bundleEmptyOption_, importance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetImportance_00300
 * @tc.name      :
 * @tc.desc      : Set bundle importance into disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetImportance_00300, Function | SmallTest | Level1)
{
    int importance = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetImportance(nullptr, importance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetImportance_00100
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00100, Function | SmallTest | Level1)
{
    int importance = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetImportance(bundleOption_, importance), (int)ERR_OK);
    int getImportance = 0;

    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetImportance(bundleOption_, getImportance), (int)ERR_OK);
    EXPECT_EQ(getImportance, 1);
}

/**
 * @tc.number    : GetImportance_00200
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00200, Function | SmallTest | Level1)
{
    int getImportance = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetImportance(bundleEmptyOption_, getImportance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetImportance_00300
 * @tc.name      :
 * @tc.desc      : Get bundle importance from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetImportance_00300, Function | SmallTest | Level1)
{
    int getImportance = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetImportance(nullptr, getImportance),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetTotalBadgeNums_00100
 * @tc.name      :
 * @tc.desc      : Set total badge nums into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetTotalBadgeNums_00100, Function | SmallTest | Level1)
{
    int num = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetTotalBadgeNums(bundleOption_, num), (int)ERR_OK);
}

/**
 * @tc.number    : SetTotalBadgeNums_00200
 * @tc.name      :
 * @tc.desc      : Set total badge nums into disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetTotalBadgeNums_00200, Function | SmallTest | Level1)
{
    int num = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetTotalBadgeNums(bundleEmptyOption_, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetTotalBadgeNums_00100
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00100, Function | SmallTest | Level1)
{
    int num = 1;
    NotificationPreferences::GetInstance().SetTotalBadgeNums(bundleOption_, num);
    int totalBadgeNum = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetTotalBadgeNums(bundleOption_, totalBadgeNum), (int)ERR_OK);
    EXPECT_EQ(totalBadgeNum, num);
}

/**
 * @tc.number    : GetTotalBadgeNums_00200
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB when bundle name is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00200, Function | SmallTest | Level1)
{
    int totalBadgeNum = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetTotalBadgeNums(bundleEmptyOption_, totalBadgeNum),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetTotalBadgeNums_00300
 * @tc.name      :
 * @tc.desc      : Get total badge nums from disturbe DB when bundleOption is null, return is ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetTotalBadgeNums_00300, Function | SmallTest | Level1)
{
    int totalBadgeNum = 0;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetTotalBadgeNums(nullptr, totalBadgeNum),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetPrivateNotificationsAllowed_00100
 * @tc.name      :
 * @tc.desc      : Set private notification allowed badge nums into disturbe DB , return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetPrivateNotificationsAllowed_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().SetPrivateNotificationsAllowed(bundleOption_, true), (int)ERR_OK);
}

/**
 * @tc.number    : SetPrivateNotificationsAllowed_00200
 * @tc.name      :
 * @tc.desc      : Set private notification allowed badge nums into disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetPrivateNotificationsAllowed_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetPrivateNotificationsAllowed(bundleEmptyOption_, true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetPrivateNotificationsAllowed_00300
 * @tc.name      :
 * @tc.desc      : Set private notification allowed badge nums into disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetPrivateNotificationsAllowed_00300, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetPrivateNotificationsAllowed(nullptr, true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetPrivateNotificationsAllowed_00100
 * @tc.name      :
 * @tc.desc      : Get private notification allowed badge nums from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetPrivateNotificationsAllowed_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().SetPrivateNotificationsAllowed(bundleOption_, true), (int)ERR_OK);
    bool allow = false;
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().GetPrivateNotificationsAllowed(bundleOption_, allow), (int)ERR_OK);
    EXPECT_EQ(allow, true);
}

/**
 * @tc.number    : GetPrivateNotificationsAllowed_00200
 * @tc.name      :
 * @tc.desc      : Get private notification allowed badge nums from disturbe DB when bundle is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetPrivateNotificationsAllowed_00200, Function | SmallTest | Level1)
{
    bool allow = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetPrivateNotificationsAllowed(bundleEmptyOption_, allow),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetPrivateNotificationsAllowed_00300
 * @tc.name      :
 * @tc.desc      : Get private notification allowed badge nums from disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetPrivateNotificationsAllowed_00300, Function | SmallTest | Level1)
{
    bool allow = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetPrivateNotificationsAllowed(nullptr, allow),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00100
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundleOption_, false),
        (int)ERR_OK);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00200
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundleEmptyOption_, false),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabledForBundle_00300
 * @tc.name      :
 * @tc.desc      : Set notification enable for bundle into disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabledForBundle_00300, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(nullptr, false),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00100
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB, return is ERR_OK.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabledForBundle(bundleOption_, false),
        (int)ERR_OK);
    bool enabled = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundleOption_, enabled),
        (int)ERR_OK);
    EXPECT_FALSE(enabled);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00200
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB when bundle name is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00200, Function | SmallTest | Level1)
{
    bool enabled = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(bundleEmptyOption_, enabled),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabledForBundle_00300
 * @tc.name      :
 * @tc.desc      : Get notification enable for bundle from disturbe DB when bundleOption is null, return is
 * ERR_ANS_INVALID_PARAM.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabledForBundle_00300, Function | SmallTest | Level1)
{
    bool enabled = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabledForBundle(nullptr, enabled),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetNotificationsEnabled_00100
 * @tc.name      :
 * @tc.desc      : Set enable notification into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabled_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabled(100, true), (int)ERR_OK);
}

/**
 * @tc.number    : SetNotificationsEnabled_00200
 * @tc.name      :
 * @tc.desc      : Set enable notification into disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, SetNotificationsEnabled_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabled(TEST_SUBSCRIBE_USER_INIT, true),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationsEnabled_00100
 * @tc.name      :
 * @tc.desc      : Get enable notification from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabled(100, true), (int)ERR_OK);
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabled(100, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);
}

/**
 * @tc.number    : GetNotificationsEnabled_00200
 * @tc.name      :
 * @tc.desc      : Same user can get enable setting, different user can not get.
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetNotificationsEnabled(100, true), (int)ERR_OK);
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabled(100, enable), (int)ERR_OK);
    EXPECT_TRUE(enable);

    enable = false;
    EXPECT_EQ(
        (int)NotificationPreferences::GetInstance().GetNotificationsEnabled(101, enable), (int)ERR_ANS_INVALID_PARAM);
    EXPECT_FALSE(enable);
}

/**
 * @tc.number    : GetNotificationsEnabled_00300
 * @tc.name      :
 * @tc.desc      : Get enable notification from disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationsEnabled_00300, Function | SmallTest | Level1)
{
    bool enable = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationsEnabled(TEST_SUBSCRIBE_USER_INIT, enable), 
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetDoNotDisturbDate_00100
 * @tc.name      :
 * @tc.desc      : Set disturbe mode into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);

    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);
}

/**
 * @tc.number    : SetDoNotDisturbDate_00200
 * @tc.name      :
 * @tc.desc      : Set disturbe mode into disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, SetDoNotDisturbDate_00200, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::ONCE, beginDate, endDate);

    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetDoNotDisturbDate(TEST_SUBSCRIBE_USER_INIT, date),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00100
 * @tc.name      :
 * @tc.desc      : Get disturbe mode from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00100, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> getDate;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetDoNotDisturbDate(SYSTEM_APP_UID, getDate), (int)ERR_OK);
    EXPECT_EQ(getDate->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    EXPECT_EQ(getDate->GetBeginDate(), beginDate);
    EXPECT_EQ(getDate->GetEndDate(), endDate);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00200
 * @tc.name      :
 * @tc.desc      : Same user can get DoNotDisturbDate setting, different user can not get.
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00200, Function | SmallTest | Level1)
{
    std::chrono::system_clock::time_point timePoint = std::chrono::system_clock::now();
    auto beginDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t beginDate = beginDuration.count();
    timePoint += std::chrono::hours(1);
    auto endDuration = std::chrono::duration_cast<std::chrono::milliseconds>(timePoint.time_since_epoch());
    int64_t endDate = endDuration.count();
    sptr<NotificationDoNotDisturbDate> date =
        new NotificationDoNotDisturbDate(NotificationConstant::DoNotDisturbType::DAILY, beginDate, endDate);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetDoNotDisturbDate(SYSTEM_APP_UID, date), (int)ERR_OK);

    sptr<NotificationDoNotDisturbDate> getDate;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetDoNotDisturbDate(SYSTEM_APP_UID, getDate), (int)ERR_OK);
    EXPECT_EQ(getDate->GetDoNotDisturbType(), NotificationConstant::DoNotDisturbType::DAILY);
    EXPECT_EQ(getDate->GetBeginDate(), beginDate);
    EXPECT_EQ(getDate->GetEndDate(), endDate);

    sptr<NotificationDoNotDisturbDate> getExsitDate;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetDoNotDisturbDate(
        NON_SYSTEM_APP_UID, getExsitDate), (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetDoNotDisturbDate_00300
 * @tc.name      :
 * @tc.desc      : Get disturbe mode from disturbe DB, when userId is -1, return is ERR_ANS_INVALID_PARAM
 */
HWTEST_F(NotificationPreferencesTest, GetDoNotDisturbDate_00300, Function | SmallTest | Level1)
{
    sptr<NotificationDoNotDisturbDate> getDate;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetDoNotDisturbDate(TEST_SUBSCRIBE_USER_INIT, getDate),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : SetHasPoppedDialog_00100
 * @tc.name      :
 * @tc.desc      : Set has popped dialog into disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, SetHasPoppedDialog_00100, Function | SmallTest | Level1)
{
    bool hasPopped = false;

    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetHasPoppedDialog(bundleOption_, hasPopped), (int)ERR_OK);
}

/**
 * @tc.number    : GetHasPoppedDialog_00100
 * @tc.name      :
 * @tc.desc      : Get has popped dialog from disturbe DB, return is ERR_OK
 */
HWTEST_F(NotificationPreferencesTest, GetHasPoppedDialog_00100, Function | SmallTest | Level1)
{
    bool popped = true;

    EXPECT_EQ((int)NotificationPreferences::GetInstance().SetHasPoppedDialog(bundleOption_, popped), (int)ERR_OK);

    bool hasPopped = false;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetHasPoppedDialog(bundleOption_, hasPopped), (int)ERR_OK);
    EXPECT_TRUE(hasPopped);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00100
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundleOption is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationBundleProperty(bundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_DB_OPERATION_FAILED);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00200
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundlename is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationBundleProperty(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : AddNotificationBundleProperty_00300
 * @tc.name      : AddNotificationBundleProperty
 * @tc.desc      : Add a notification BundleProperty into distrube DB when bundlename is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, AddNotificationBundleProperty_00300, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().AddNotificationBundleProperty(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00100
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundlename is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00100, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationAllSlots(bundleOption_),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00200
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00200, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationAllSlots(bundleEmptyOption_),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : RemoveNotificationAllSlots_00300
 * @tc.name      : RemoveNotificationAllSlots
 * @tc.desc      : Test RemoveNotificationAllSlots function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, RemoveNotificationAllSlots_00300, Function | SmallTest | Level1)
{
    EXPECT_EQ((int)NotificationPreferences::GetInstance().RemoveNotificationAllSlots(nullptr),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00100
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundlename is null,
 *                 return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00100, Function | SmallTest | Level1)
{
    uint64_t num = 1;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlotsNumForBundle(bundleOption_, num),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00200
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00200, Function | SmallTest | Level1)
{
    uint64_t num = 2;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlotsNumForBundle(bundleEmptyOption_, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : GetNotificationSlotsNumForBundle_00300
 * @tc.name      : GetNotificationSlotsNumForBundle
 * @tc.desc      : Test GetNotificationSlotsNumForBundle function when bundleOption is null,
 *                 return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, GetNotificationSlotsNumForBundle_00300, Function | SmallTest | Level1)
{
    uint64_t num = 2;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().GetNotificationSlotsNumForBundle(nullptr, num),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSlotForCreateSlot_00100
 * @tc.name      : CheckSlotForCreateSlot
 * @tc.desc      : Test CheckSlotForCreateSlot function when slot is null, return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForCreateSlot_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForCreateSlot(bundleOption_, nullptr, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForCreateSlot_00200
 * @tc.name      : CheckSlotForCreateSlot
 * @tc.desc      : Test CheckSlotForCreateSlot function, return ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForCreateSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForCreateSlot(bundleOption_, slot, info),
        (int)ERR_OK);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00100
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function after add a notification slot,
 * return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00100, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::OTHER, info), (int)ERR_OK);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00200
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function, return is ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST,
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::OTHER, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForRemoveSlot_00300
 * @tc.name      : CheckSlotForRemoveSlot
 * @tc.desc      : Test CheckSlotForRemoveSlot function after add a notification slot, return is ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForRemoveSlot_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForRemoveSlot(
        bundleOption_, NotificationConstant::SlotType::CONTENT_INFORMATION, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00100
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when slot is null, return is ERR_ANS_INVALID_PARAM.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00100, Function | SmallTest | Level1)
{
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    NotificationPreferencesInfo info;
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForUpdateSlot(bundleOption_, nullptr, info),
        (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00200
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when bundle not existed, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00200, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_BUNDLE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00300
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function when slot is different type, return is
 * ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00300, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::CONTENT_INFORMATION);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_ANS_PREFERENCES_NOTIFICATION_SLOT_TYPE_NOT_EXIST);
}

/**
 * @tc.number    : CheckSlotForUpdateSlot_00400
 * @tc.name      : CheckSlotForUpdateSlot
 * @tc.desc      : Test CheckSlotForUpdateSlot function after add notification slot, return is ERR_OK.
 * @tc.require   : issueI5SR8J
 */
HWTEST_F(NotificationPreferencesTest, CheckSlotForUpdateSlot_00400, Function | SmallTest | Level1)
{
    NotificationPreferencesInfo info;
    TestAddNotificationSlot(info);
    sptr<NotificationSlot> slot = new NotificationSlot(NotificationConstant::SlotType::OTHER);
    EXPECT_EQ((int)NotificationPreferences::GetInstance().CheckSlotForUpdateSlot(bundleOption_, slot, info),
        (int)ERR_OK);
}
}  // namespace Notification
}  // namespace OHOS
