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

#include <gtest/gtest.h>

#include "reminder_data_manager.h"
#include "reminder_request_calendar.h"
#include "reminder_datashare_helper.h"
#include "reminder_calendar_share_table.h"

#include "mock_service_registry.h"
#include "mock_datashare_helper.h"
#include "mock_datashare_result_set.h"
#include "mock_reminder_data_manager.h"
#include "mock_reminder_bundle_manager_helper.h"

using namespace testing::ext;
namespace OHOS::Notification {
class ReminderDataShareHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ReminderDataShareHelper_001
 * @tc.desc: test ReminderDataShareHelper::RegisterObserver function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_001, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;
    ReminderDataManager::InitInstance();

    // helper is nullptr
    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    // TryRegisterObserverExt is nok
    EXPECT_CALL(*mockHelper, TryRegisterObserverExt(testing::_, testing::_, testing::_, testing::_)).Times(1)
        .WillOnce(testing::Return(-1));
    ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, false);
    // TryRegisterObserverExt is ok
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, TryRegisterObserverExt(testing::_, testing::_, testing::_, testing::_)).Times(1)
        .WillOnce(testing::Return(0));
    ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, true);
    EXPECT_NE(ReminderDataShareHelper::GetInstance().observer_, nullptr);
    // observer_ is not nullptr
    ret = ReminderDataShareHelper::GetInstance().RegisterObserver();
    EXPECT_EQ(ret, true);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_002
 * @tc.desc: test ReminderDataShareHelper::UnRegisterObserver function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_002, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;

    // helper is nullptr
    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().UnRegisterObserver();
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, TryUnregisterObserverExt(testing::_, testing::_, testing::_)).Times(1)
        .WillOnce(testing::Return(0));
    ret = ReminderDataShareHelper::GetInstance().UnRegisterObserver();
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().observer_, nullptr);
    // observer_ is nullptr
    ret = ReminderDataShareHelper::GetInstance().UnRegisterObserver();
    EXPECT_EQ(ret, true);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_003
 * @tc.desc: test ReminderDataShareHelper::Query function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_003, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;

    // helper is nullptr
    std::map<std::string, sptr<ReminderRequest>> reminders;
    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().Query(reminders);
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);

    // Query is nullptr
    reminders.clear();
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 2;
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(nullptr));
    ret = ReminderDataShareHelper::GetInstance().Query(reminders);
    EXPECT_EQ(ret, false);

    // GoToNextRow nok
    reminders.clear();
    MockDataShareResultSet* mockResultSet = new MockDataShareResultSet;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    resultSet.reset(mockResultSet);
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(resultSet));
    EXPECT_CALL(*mockResultSet, GoToNextRow()).Times(1).WillOnce(testing::Return(-1));
    ret = ReminderDataShareHelper::GetInstance().Query(reminders);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(reminders.size(), 0);

    // GoToNextRow ok
    reminders.clear();
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(resultSet));
    EXPECT_CALL(*mockResultSet, GoToNextRow()).Times(2).WillOnce(testing::Return(0))
        .WillOnce(testing::Return(-1));
    EXPECT_CALL(*mockResultSet, GetColumnIndex(testing::_, testing::_)).Times(11)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(-1), testing::Return(0)))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(-1), testing::Return(0)))
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(0), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetLong(testing::_, testing::_)).Times(1)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(1761817241000), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetInt(testing::_, testing::_)).Times(3)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(1), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetString(testing::_, testing::_)).Times(5)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>("test"), testing::Return(0)));
    ret = ReminderDataShareHelper::GetInstance().Query(reminders);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(reminders.size(), 1);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_004
 * @tc.desc: test ReminderDataShareHelper::Query function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_004, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;

    std::string uriStr = "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100"
        "?Proxy=true&key=focus_mode_enable";
    Uri enableUri(uriStr);
    std::string enable;
    // helper is nullptr
    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().Query(enableUri, "focus_mode_enable", enable);
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);

    // Query is nullptr
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(nullptr));
    ret = ReminderDataShareHelper::GetInstance().Query(enableUri, "focus_mode_enable", enable);
    EXPECT_EQ(ret, false);

    // GoToFirstRow nok
    MockDataShareResultSet* mockResultSet = new MockDataShareResultSet;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    resultSet.reset(mockResultSet);
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(resultSet));
    EXPECT_CALL(*mockResultSet, GoToFirstRow()).Times(1).WillOnce(testing::Return(-1));
    EXPECT_CALL(*mockResultSet, Close()).Times(1).WillOnce(testing::Return(0));
    ret = ReminderDataShareHelper::GetInstance().Query(enableUri, "focus_mode_enable", enable);
    EXPECT_EQ(ret, true);

    // GoToFirstRow ok
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(resultSet));
    EXPECT_CALL(*mockResultSet, GoToFirstRow()).Times(1).WillOnce(testing::Return(0));
    EXPECT_CALL(*mockResultSet, GetColumnIndex(testing::_, testing::_)).Times(1)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(0), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetString(testing::_, testing::_)).Times(1)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>("test"), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, Close()).Times(1).WillOnce(testing::Return(0));
    ret = ReminderDataShareHelper::GetInstance().Query(enableUri, "focus_mode_enable", enable);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(enable, "test");
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_005
 * @tc.desc: test ReminderDataShareHelper::Update function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_005, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;

    // helper is nullptr
    MockDataShareHelper::MockCreate(-1, nullptr);
    bool ret = ReminderDataShareHelper::GetInstance().Update("test", 1);
    EXPECT_EQ(ret, false);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);

    // UpdateEx nok
    std::pair<int32_t, int32_t> result{-1, 0};
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, UpdateEx(testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(result));
    ret = ReminderDataShareHelper::GetInstance().Update("test", 1);
    EXPECT_EQ(ret, true);

    // UpdateEx ok
    std::pair<int32_t, int32_t> result1{0, 0};
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, UpdateEx(testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(result1));
    ret = ReminderDataShareHelper::GetInstance().Update("test", 1);
    EXPECT_EQ(ret, true);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_006
 * @tc.desc: test ReminderDataShareHelper::StartDataExtension function
 * ReminderDataShareHelper::GetCacheReminders
 * ReminderDataShareHelper::InsertCacheReminders
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_006, Level1)
{
    ReminderDataShareHelper::GetInstance().StartDataExtension(1);
    std::map<std::string, sptr<ReminderRequest>> reminders;
    ReminderDataShareHelper::GetInstance().InsertCacheReminders(reminders);
    reminders = ReminderDataShareHelper::GetInstance().GetCacheReminders();
    EXPECT_EQ(reminders.size(), 0);

    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    reminders["test"] = reminder;
    ReminderDataShareHelper::GetInstance().InsertCacheReminders(reminders);
    reminders.clear();
    reminders = ReminderDataShareHelper::GetInstance().GetCacheReminders();
    EXPECT_EQ(reminders.size(), 1);
}

/**
 * @tc.name: ReminderDataShareHelper_007
 * @tc.desc: test ReminderDataShareHelper::UpdateCalendarUid function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_007, Level1)
{
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    AppExecFwk::BundleInfo bundleInfo;
    MockReminderBundleManagerHelper::MockGetBundleInfo(false, bundleInfo);
    ReminderDataShareHelper::GetInstance().UpdateCalendarUid();
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().rdbVersion_, 0);

    MockReminderBundleManagerHelper::MockGetBundleInfo(true, bundleInfo);
    ReminderDataShareHelper::GetInstance().UpdateCalendarUid();
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().rdbVersion_, 0);

    AppExecFwk::HapModuleInfo moduleInfo;
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    MockReminderBundleManagerHelper::MockGetBundleInfo(true, bundleInfo);
    ReminderDataShareHelper::GetInstance().UpdateCalendarUid();
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().rdbVersion_, 0);

    AppExecFwk::Metadata data;
    data.name = "test";
    data.value = "1";
    moduleInfo.metadata.push_back(data);
    data.name = "hmos.calendardata.reminderDbVersion";
    data.value = "1";
    moduleInfo.metadata.push_back(data);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    MockReminderBundleManagerHelper::MockGetBundleInfo(true, bundleInfo);
    ReminderDataShareHelper::GetInstance().UpdateCalendarUid();
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().rdbVersion_, 1);

    moduleInfo.metadata.clear();
    bundleInfo.hapModuleInfos.clear();
    data.name = "hmos.calendardata.reminderDbVersion";
    data.value = "2";
    moduleInfo.metadata.push_back(data);
    bundleInfo.hapModuleInfos.push_back(moduleInfo);
    MockReminderBundleManagerHelper::MockGetBundleInfo(true, bundleInfo);
    ReminderDataShareHelper::GetInstance().UpdateCalendarUid();
    EXPECT_EQ(ReminderDataShareHelper::GetInstance().rdbVersion_, 2);
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
}

/**
 * @tc.name: ReminderDataShareHelper_008
 * @tc.desc: test ReminderDataShareHelper::OnDataInsertOrDelete function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_008, Level1)
{
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareInsertOrDelete_, false);
    MockReminderDataManager::ResetFlag();

    ReminderDataManager::InitInstance();
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareInsertOrDelete_, true);
    MockReminderDataManager::ResetFlag();

    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    ReminderDataShareHelper::GetInstance().OnDataInsertOrDelete();
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareInsertOrDelete_, true);
    MockReminderDataManager::ResetFlag();
}

/**
 * @tc.name: ReminderDataShareHelper_009
 * @tc.desc: test ReminderDataShareHelper::OnDataUpdate function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_009, Level1)
{
    ReminderDataManager::REMINDER_DATA_MANAGER = nullptr;
    DataShare::DataShareObserver::ChangeInfo info;
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareUpdate_, false);
    MockReminderDataManager::ResetFlag();

    ReminderDataManager::InitInstance();
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareUpdate_, true);
    MockReminderDataManager::ResetFlag();

    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    ReminderDataShareHelper::GetInstance().OnDataUpdate(info);
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareUpdate_, true);
    MockReminderDataManager::ResetFlag();
}

/**
 * @tc.name: ReminderDataShareHelper_010
 * @tc.desc: test ReminderDataShareHelper::CreateDataShareHelper function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_010, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;
    ReminderDataManager::InitInstance();

    MockDataShareHelper::MockCreate(-1, nullptr);
    auto ret = ReminderDataShareHelper::GetInstance().CreateDataShareHelper("test");
    EXPECT_EQ(ret, nullptr);

    MockDataShareHelper::MockCreate(0, nullptr);
    ret = ReminderDataShareHelper::GetInstance().CreateDataShareHelper("test");
    EXPECT_EQ(ret, nullptr);

    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);
    ret = ReminderDataShareHelper::GetInstance().CreateDataShareHelper("test");
    EXPECT_NE(ret, nullptr);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_011
 * @tc.desc: test ReminderDataShareHelper::Query function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_011, Level1)
{
    MockDataShareHelper* mockHelper = new MockDataShareHelper;

    // helper is nullptr
    std::map<std::string, sptr<ReminderRequest>> reminders;
    std::shared_ptr<DataShare::DataShareHelper> helper;
    helper.reset(mockHelper);
    MockDataShareHelper::MockCreate(0, helper);

    // GoToNextRow nok
    MockDataShareResultSet* mockResultSet = new MockDataShareResultSet;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    resultSet.reset(mockResultSet);
    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;

    // GoToNextRow ok
    EXPECT_CALL(*mockHelper, Release()).Times(1).WillOnce(testing::Return(true));
    EXPECT_CALL(*mockHelper, Query(testing::_, testing::_, testing::_, testing::_))
        .Times(1).WillOnce(testing::Return(resultSet));
    EXPECT_CALL(*mockResultSet, GoToNextRow()).Times(3)
        .WillOnce(testing::Return(0))
        .WillOnce(testing::Return(0))
        .WillOnce(testing::Return(-1));
    EXPECT_CALL(*mockResultSet, GetColumnIndex(testing::_, testing::_)).Times(11)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(0), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetLong(testing::_, testing::_)).Times(1)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(1761817241000), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetInt(testing::_, testing::_)).Times(5)
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(0), testing::Return(0)))
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(1), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetString(testing::_, testing::_)).Times(5)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>("test"), testing::Return(0)));
    bool ret = ReminderDataShareHelper::GetInstance().Query(reminders);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(reminders.size(), 1);
    MockDataShareHelper::MockCreate(-1, nullptr);
}

/**
 * @tc.name: ReminderDataShareHelper_012
 * @tc.desc: test ReminderDataShareHelper::CreateReminder function
 * DataShare::DataShareObserver::ChangeInfo
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_012, Level1)
{
    DataShare::DataShareObserver::ChangeInfo info;
    auto result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 0);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    info.valueBuckets_.resize(1);
    result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 1);

    DataShare::DataShareObserver::ChangeInfo::Value alarmTime = static_cast<double>(1761374864000);
    info.valueBuckets_[0][ReminderCalendarShareTable::ALARM_TIME] = alarmTime;
    DataShare::DataShareObserver::ChangeInfo::Value ends = static_cast<double>(1761378464000);
    info.valueBuckets_[0][ReminderCalendarShareTable::END] = ends;
    result = ReminderDataShareHelper::GetInstance().CreateReminder(info);
    EXPECT_EQ(result.size(), 1);
    for (auto& [key, value] : result) {
        EXPECT_EQ(value->GetTriggerTimeInMilli(), 1761374864000);
        EXPECT_EQ(value->GetAutoDeletedTime(), 1761378464000);
        break;
    }
}

/**
 * @tc.name: ReminderDataShareHelper_013
 * @tc.desc: test ReminderDataShareHelper::InitBaseInfo function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_013, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    DataShare::DataShareObserver::ChangeInfo info;
    info.valueBuckets_.resize(1);
    ReminderDataShareHelper::GetInstance().InitBaseInfo(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetIdentifier(), "");

    DataShare::DataShareObserver::ChangeInfo::Value id = static_cast<double>(15);
    info.valueBuckets_[0][ReminderCalendarShareTable::ID] = id;
    DataShare::DataShareObserver::ChangeInfo::Value eventId = static_cast<double>(15);
    info.valueBuckets_[0][ReminderCalendarShareTable::EVENT_ID] = eventId;
    DataShare::DataShareObserver::ChangeInfo::Value slotType = static_cast<double>(0);
    info.valueBuckets_[0][ReminderCalendarShareTable::SLOT_TYPE] = slotType;
    DataShare::DataShareObserver::ChangeInfo::Value title = std::string("test");
    info.valueBuckets_[0][ReminderCalendarShareTable::TITLE] = title;
    DataShare::DataShareObserver::ChangeInfo::Value content = std::string("InitBaseInfo");
    info.valueBuckets_[0][ReminderCalendarShareTable::CONTENT] = content;
    DataShare::DataShareObserver::ChangeInfo::Value buttons = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::BUTTONS] = buttons;
    DataShare::DataShareObserver::ChangeInfo::Value wantAgent = std::string("");
    info.valueBuckets_[0][ReminderCalendarShareTable::WANT_AGENT] = wantAgent;
    DataShare::DataShareObserver::ChangeInfo::Value identifier = std::string("test_015_InitBaseInfo");
    info.valueBuckets_[0][ReminderCalendarShareTable::IDENTIFIER] = identifier;
    ReminderDataShareHelper::GetInstance().InitBaseInfo(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetReminderId(), 15);
    EXPECT_EQ(reminder->GetNotificationId(), 15);
    EXPECT_EQ(reminder->GetTitle(), "test");
    EXPECT_EQ(reminder->GetContent(), "InitBaseInfo");
    EXPECT_EQ(reminder->GetIdentifier(), "test_015_InitBaseInfo");
}

/**
 * @tc.name: ReminderDataShareHelper_014
 * @tc.desc: test ReminderDataShareHelper::BuildReminderV1 function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_014, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    MockDataShareResultSet* mockResultSet = new MockDataShareResultSet;
    std::shared_ptr<DataShare::DataShareResultSet> resultSet;
    resultSet.reset(mockResultSet);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    reminder->SetTimeInterval(0);
    ReminderDataShareHelper::GetInstance().BuildReminderV1(resultSet, reminder);
    EXPECT_EQ(reminder->GetTimeInterval(), 0);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 1;
    EXPECT_CALL(*mockResultSet, GetColumnIndex(testing::_, testing::_)).Times(8)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(0), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetLong(testing::_, testing::_)).Times(2)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(300), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetInt(testing::_, testing::_)).Times(2)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(1), testing::Return(0)));
    EXPECT_CALL(*mockResultSet, GetString(testing::_, testing::_)).Times(4)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>("test"), testing::Return(0)));
    ReminderDataShareHelper::GetInstance().BuildReminderV1(resultSet, reminder);
    EXPECT_EQ(reminder->GetTimeInterval(), 300);
    EXPECT_EQ(reminder->GetSnoozeTimes(), 1);
    EXPECT_EQ(reminder->GetRingDuration(), 300);
    EXPECT_EQ(reminder->GetSnoozeContent(), "test");
    EXPECT_EQ(reminder->GetCustomRingUri(), "test");
}

/**
 * @tc.name: ReminderDataShareHelper_016
 * @tc.desc: test ReminderDataShareHelper::BuildReminderV1 function
 * DataShare::DataShareObserver::ChangeInfo::VBucket
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_016, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    DataShare::DataShareObserver::ChangeInfo info;
    info.valueBuckets_.resize(1);

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 0;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetSnoozeContent(), "");

    ReminderDataShareHelper::GetInstance().rdbVersion_ = 1;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetSnoozeContent(), "");

    DataShare::DataShareObserver::ChangeInfo::Value timeInterval = static_cast<double>(600);
    info.valueBuckets_[0][ReminderCalendarShareTable::TIME_INTERVAL] = timeInterval;
    DataShare::DataShareObserver::ChangeInfo::Value snoozeTimes = static_cast<double>(10);
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_TIMES] = snoozeTimes;
    DataShare::DataShareObserver::ChangeInfo::Value ringDuration = static_cast<double>(10);
    info.valueBuckets_[0][ReminderCalendarShareTable::RING_DURATION] = ringDuration;
    DataShare::DataShareObserver::ChangeInfo::Value type = static_cast<double>(1);
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_SLOT_TYPE] = type;
    DataShare::DataShareObserver::ChangeInfo::Value snoozeContent = "snooze BuildReminderV1";
    info.valueBuckets_[0][ReminderCalendarShareTable::SNOOZE_CONTENT] = snoozeContent;
    DataShare::DataShareObserver::ChangeInfo::Value expiredContent = "expired BuildReminderV1";
    info.valueBuckets_[0][ReminderCalendarShareTable::EXPIRED_CONTENT] = expiredContent;
    std::string value = R"({"pkgName": "com.aaa.aaa", "abilityName": "Entry"})";
    DataShare::DataShareObserver::ChangeInfo::Value wantAgent = value;
    info.valueBuckets_[0][ReminderCalendarShareTable::MAX_SCREEN_WANT_AGENT] = wantAgent;
    DataShare::DataShareObserver::ChangeInfo::Value uri = "ring";
    info.valueBuckets_[0][ReminderCalendarShareTable::CUSTOM_RING_URI] = uri;
    ReminderDataShareHelper::GetInstance().BuildReminderV1(info.valueBuckets_[0], reminder);
    EXPECT_EQ(reminder->GetTimeInterval(), 600);
    EXPECT_EQ(reminder->GetSnoozeTimes(), 10);
    EXPECT_EQ(reminder->GetRingDuration(), 10);
    int32_t result = static_cast<int32_t>(reminder->GetSnoozeSlotType());
    EXPECT_EQ(result, 1);
    EXPECT_EQ(reminder->GetSnoozeContent(), "snooze BuildReminderV1");
    EXPECT_EQ(reminder->GetExpiredContent(), "expired BuildReminderV1");
    EXPECT_EQ(reminder->GetCustomRingUri(), "ring");
    EXPECT_EQ(reminder->maxScreenWantAgentInfo_->pkgName, "com.aaa.aaa");
    EXPECT_EQ(reminder->maxScreenWantAgentInfo_->abilityName, "Entry");
}

/**
 * @tc.name: ReminderDataShareHelper_017
 * @tc.desc: test ReminderDataObserver::OnChange function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_017, Level1)
{
    ReminderDataShareHelper::ReminderDataObserver observer;
    DataShare::DataShareObserver::ChangeInfo info;
    info.changeType_ = DataShare::DataShareObserver::ChangeType::INSERT;
    observer.OnChange(info);
    info.changeType_ = DataShare::DataShareObserver::ChangeType::UPDATE;
    observer.OnChange(info);
    info.changeType_ = DataShare::DataShareObserver::ChangeType::DELETE;
    observer.OnChange(info);
    info.changeType_ = DataShare::DataShareObserver::ChangeType::OTHER;
    observer.OnChange(info);
    sleep(2);
    EXPECT_EQ(MockReminderDataManager::callOnDataShareInsertOrDelete_, true);
}

/**
 * @tc.name: ReminderDataShareHelper_018
 * @tc.desc: test ReminderDataObserver::InitNormalInfo function
 * @tc.type: FUNC
 * @tc.require: issueI5YTF3
 */
HWTEST_F(ReminderDataShareHelperTest, ReminderDataShareHelper_018, Level1)
{
    sptr<ReminderRequest> reminder = sptr<ReminderRequestCalendar>::MakeSptr();
    ReminderDataShareHelper::GetInstance().uid_ = 200200100;
    ReminderDataShareHelper::GetInstance().InitNormalInfo(reminder);
    EXPECT_EQ(reminder->GetUid(), 200200100);
    ReminderDataShareHelper::GetInstance().uid_ = -1;
    MockReminderBundleManagerHelper::MockGetDefaultUidByBundleName(100100100);
    ReminderDataShareHelper::GetInstance().InitNormalInfo(reminder);
    EXPECT_EQ(reminder->GetUid(), 100100100);
}
}