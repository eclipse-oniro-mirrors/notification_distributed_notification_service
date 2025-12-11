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

#include "gtest/gtest.h"

#define private public

#include "health_white_list_util.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"
#include "notification_preferences.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
class HealthWhiteListUtilTest : public testing::Test {
public:
    HealthWhiteListUtilTest()
    {}
    ~HealthWhiteListUtilTest()
    {}
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp();
    void TearDown() {};

public:
    std::shared_ptr<HealthWhiteListUtil> healthWhiteListUtil_;
};

void HealthWhiteListUtilTest::SetUp(void)
{
    healthWhiteListUtil_ = DelayedSingleton<HealthWhiteListUtil>::GetInstance();
}

/**
 * @tc.name: ParseDbDate_100
 * @tc.desc: Test ParseDbDate when db is empty
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, ParseDbDate_100, Function | SmallTest | Level1)
{
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "", -1);
    nlohmann::json bundles;
    bool result = healthWhiteListUtil_->ParseDbDate(bundles);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: ParseDbDate_200
 * @tc.desc: Test ParseDbDate when db is invalid value
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, ParseDbDate_200, Function | SmallTest | Level1)
{
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "invalidJson", -1);
    nlohmann::json bundles;
    bool result = healthWhiteListUtil_->ParseDbDate(bundles);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: ParseDbDate_300
 * @tc.desc: Test ParseDbDate when db is effect value
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, ParseDbDate_300, Function | SmallTest | Level1)
{
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    nlohmann::json bundles;
    bool result = healthWhiteListUtil_->ParseDbDate(bundles);
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckInLiveViewList_100
 * @tc.desc: Test CheckInLiveViewList when bundleName is empty
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, CheckInLiveViewList_100, Function | SmallTest | Level1)
{
    nlohmann::json bundles;
    bool result = healthWhiteListUtil_->CheckInLiveViewList("");
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckInLiveViewList_200
 * @tc.desc: Test CheckInLiveViewList when parseDate fail
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, CheckInLiveViewList_200, Function | SmallTest | Level1)
{
    nlohmann::json bundles;
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "invalidJson", -1);
    bool result = healthWhiteListUtil_->CheckInLiveViewList("bundleName");
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckInLiveViewList_300
 * @tc.desc: Test CheckInLiveViewList when in list
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, CheckInLiveViewList_300, Function | SmallTest | Level1)
{
    nlohmann::json bundles;
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    bool result = healthWhiteListUtil_->CheckInLiveViewList("testBundleName");
    ASSERT_EQ(result, true);
}

/**
 * @tc.name: CheckInLiveViewList_400
 * @tc.desc: Test CheckInLiveViewList when in list
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, CheckInLiveViewList_400, Function | SmallTest | Level1)
{
    nlohmann::json bundles;
    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    bool result = healthWhiteListUtil_->CheckInLiveViewList("outList");
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: AddExtendFlagForRequest_100
 * @tc.desc: Test AddExtendFlagForRequest when notification empty
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_100, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    EXPECT_TRUE(notifications.empty());
}

/**
 * @tc.name: AddExtendFlagForRequest_200
 * @tc.desc: Test AddExtendFlagForRequest when parseData fail
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_200, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<Notification> notification = new Notification();
    notifications.push_back(notification);

    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "invalidJson", -1);
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    EXPECT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: AddExtendFlagForRequest_300
 * @tc.desc: Test AddExtendFlagForRequest when bundleName is null
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_300, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationRequest> request = new NotificationRequest();
    sptr<Notification> notification = new Notification(request);
    notifications.push_back(notification);

    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    EXPECT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: AddExtendFlagForRequest_400
 * @tc.desc: Test AddExtendFlagForRequest when slotType not liveView
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_400, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("testBundleName");
    sptr<Notification> notification = new Notification(request);
    notifications.push_back(notification);

    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    EXPECT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: AddExtendFlagForRequest_500
 * @tc.desc: Test AddExtendFlagForRequest when extendInfo is not null and inlist
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_500, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("testBundleName");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    shared_ptr<AAFwk::WantParams> extendInfo = std::make_shared<AAFwk::WantParams>();
    request->SetExtendInfo(extendInfo);
    sptr<Notification> notification = new Notification(request);
    notifications.push_back(notification);

    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    EXPECT_EQ(notifications.size(), 1);
}

/**
 * @tc.name: AddExtendFlagForRequest_600
 * @tc.desc: Test AddExtendFlagForRequest when extendInfo is  null and out list
 * @tc.type: FUNC
 */
HWTEST_F(HealthWhiteListUtilTest, AddExtendFlagForRequest_600, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notifications;
    sptr<NotificationRequest> request = new NotificationRequest();
    request->SetOwnerBundleName("outList");
    request->SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    sptr<Notification> notification = new Notification(request);
    notifications.push_back(notification);

    NotificationPreferences::GetInstance()->SetKvToDb("HEALTH_BUNDLE_WHITE_LIST", "[\"testBundleName\"]", -1);
    healthWhiteListUtil_->AddExtendFlagForRequest(notifications);
    std::shared_ptr<AAFwk::WantParams> extendInfo = request->GetExtendInfo();
    EXPECT_TRUE(extendInfo != nullptr);
    EXPECT_TRUE(extendInfo->HasParam("out_health_white_list"));
}
}
}